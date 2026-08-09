<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingRequestComparator;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;
use Throwable;

/**
 * Handles paging search request logic using per-connection generator state.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerPagingHandler implements ServerProtocolHandlerInterface
{
    use ServerSearchTrait;
    use MatchedDnAccessFilterTrait;

    public function __construct(
        private readonly LdapBackendInterface $backend,
        private readonly FilterEvaluatorInterface $filterEvaluator,
        private readonly AccessControlInterface $accessControl,
        private readonly RequestHistory $requestHistory,
        private readonly Schema $schema,
        private readonly PagingRequestComparator $requestComparator = new PagingRequestComparator(),
        private readonly SearchLimits $limits = new SearchLimits(),
        private readonly ?EventLogger $eventLogger = null,
    ) {}

    /**
     * @inheritDoc
     * @throws ProtocolException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $pagingRequest = $this->findOrMakePagingRequest($message);
        $searchRequest = $this->getSearchRequestFromMessage($message);

        $response = null;
        $controls = [];
        $entriesReturned = 0;
        $failure = null;
        try {
            $this->assertBaseDnProvided($searchRequest);

            $response = $this->handlePaging(
                $pagingRequest,
                $message,
                $token,
            );
            if ($response->isSizeLimitExceeded()) {
                $searchResult = SearchResult::makeSizeLimitResult(
                    $response->getEntries(),
                    (string) $searchRequest->getBaseDn(),
                );
                $controls[] = new PagingControl(0, '');
            } else {
                $searchResult = SearchResult::makeSuccessResult(
                    $response->getEntries(),
                    (string) $searchRequest->getBaseDn(),
                );
                $controls[] = new PagingControl(
                    $response->getRemaining(),
                    $response->isComplete()
                        ? ''
                        : $pagingRequest->getNextCookie(),
                );
            }
            $entriesReturned = $response->getEntries()->count();
        } catch (OperationException $e) {
            $failure = $e;
            $matchedDn = $this->filterMatchedDn(
                $e->getMatchedDn(),
                $token,
                $this->backend,
                $this->accessControl,
            );
            $searchResult = SearchResult::makeErrorResult(
                $e->getCode(),
                $matchedDn !== null
                    ? $matchedDn->toString()
                    : '',
                $e->getMessage(),
            );
            $controls[] = new PagingControl(0, '');
        }

        $sortResponse = $this->sortingResponseControl(
            $this->sortingControl($message),
            $this->schema,
        );
        if ($sortResponse !== null) {
            $controls[] = $sortResponse;
        }

        $pagingRequest->markProcessed();

        /**
         * Per Section 3 of RFC 2696:
         *
         *     If, for any reason, the server cannot resume a paged search operation
         *     for a client, then it SHOULD return the appropriate error in a
         *     searchResultDone entry. If this occurs, both client and server should
         *     assume the paged result set is closed and no longer resumable.
         *
         * If a search result is anything other than success, or the paging is complete,
         * remove the paging request and discard the generator.
         */
        if (($response && $response->isComplete()) || $searchResult->getState()->resultCode !== ResultCode::SUCCESS) {
            $this->requestHistory->pagingRequest()->remove($pagingRequest);
            $this->requestHistory->removePagingGenerator($pagingRequest->getNextCookie());
        }

        $outcome = $failure !== null
            ? SearchOperationResult::failure(
                $message,
                $failure,
            )
            : SearchOperationResult::success(
                $message,
                $entriesReturned,
            );

        // A page is pre-collected and bounded, so it is bulk-sent without mid-page cancel polling.
        return ResponseStream::of(
            $this->buildResponseStream(
                $searchResult,
                $message->getMessageId(),
                new Cancellation(),
                ...$controls,
            ),
            $outcome,
        );
    }

    /**
     * @throws OperationException
     */
    private function handlePaging(
        PagingRequest $pagingRequest,
        LdapMessageRequest $message,
        TokenInterface $token,
    ): PagingResponse {
        if (!$pagingRequest->isPagingStart()) {
            return $this->handleExistingCookie(
                $pagingRequest,
                $message,
                $token,
            );
        }

        return $this->handlePagingStart(
            $pagingRequest,
            $token,
        );
    }

    /**
     * @throws OperationException
     */
    private function handlePagingStart(
        PagingRequest $pagingRequest,
        TokenInterface $token,
    ): PagingResponse {
        $searchRequest = $pagingRequest->getSearchRequest();

        // Paged searches use the paged lookthrough limit (falls back to the regular one when unset).
        $result = $this->backend->search(
            $searchRequest,
            $this->subentryVisibility($pagingRequest->controls()),
            $pagingRequest->controls(),
            new SearchLimits(
                maxSearchTimeLimit: $this->limits->maxSearchTimeLimit,
                maxSearchLookthrough: $this->limits->effectivePagedLookthrough(),
            ),
        );
        $generator = $result->entries;

        $collected = $this->collectFromGenerator(
            $generator,
            $pagingRequest->getSize(),
            $searchRequest,
            $token,
            $this->projectionFor($searchRequest),
        );

        return $this->buildPagingResponse(
            $collected,
            $pagingRequest,
            $generator,
        );
    }

    /**
     * @throws OperationException
     */
    private function handleExistingCookie(
        PagingRequest $pagingRequest,
        LdapMessageRequest $message,
        TokenInterface $token,
    ): PagingResponse {
        $newPagingRequest = $this->makePagingRequest($message);

        if (!$this->requestComparator->compare($pagingRequest, $newPagingRequest)) {
            throw new OperationException(
                'The search request and controls must be identical between paging requests.',
                ResultCode::OPERATIONS_ERROR,
            );
        }

        $pagingRequest->updatePagingControl($this->getPagingControlFromMessage($message));

        if ($pagingRequest->isAbandonRequest()) {
            return PagingResponse::makeFinal(new Entries());
        }

        $currentCookie = $pagingRequest->getNextCookie();
        $generator = $this->requestHistory->getPagingGenerator($currentCookie);

        if ($generator === null) {
            throw new OperationException(
                'The paging session could not be resumed.',
                ResultCode::OPERATIONS_ERROR,
            );
        }

        $this->requestHistory->removePagingGenerator($currentCookie);

        $collected = $this->collectFromGenerator(
            $generator,
            $pagingRequest->getSize(),
            $pagingRequest->getSearchRequest(),
            $token,
            $this->projectionFor($pagingRequest->getSearchRequest()),
        );

        return $this->buildPagingResponse(
            $collected,
            $pagingRequest,
            $generator,
        );
    }

    /**
     * @throws OperationException
     */
    private function buildPagingResponse(
        CollectedPage $collected,
        PagingRequest $pagingRequest,
        Generator $generator,
    ): PagingResponse {
        if ($collected->isSizeLimitExceeded) {
            return PagingResponse::makeSizeLimitExceeded(new Entries(...$collected->entries));
        }

        $nextCookie = $this->generateCookie();
        $pagingRequest->updateNextCookie($nextCookie);

        if ($collected->isGeneratorExhausted) {
            return PagingResponse::makeFinal(new Entries(...$collected->entries));
        }

        $this->requestHistory->storePagingGenerator(
            $nextCookie,
            $generator,
        );

        return PagingResponse::make(
            new Entries(...$collected->entries),
        );
    }

    /**
     * Advances the generator, collecting up to $pageSize entries that pass the filter.
     *
     * Also enforces the client's sizeLimit from the SearchRequest. When the sizeLimit is
     * reached before the generator is exhausted, $isSizeLimitExceeded is true in the return.
     */
    private function collectFromGenerator(
        Generator $generator,
        int $pageSize,
        SearchRequest $request,
        TokenInterface $token,
        AttributeProjection $projection,
    ): CollectedPage {
        $page = [];
        $effectivePageSize = $this->effectiveSizeLimit(
            $pageSize,
            $this->limits->maxSearchPageSize,
        );
        $pageLimit = $effectivePageSize > 0
            ? $effectivePageSize
            : null;
        $sizeLimit = $this->effectiveSizeLimit(
            $request->getSizeLimit(),
            $this->limits->maxSearchSize,
        );
        $filter = $request->getFilter();

        while ($generator->valid() && $this->pageHasCapacity($page, $pageLimit)) {
            $entry = $generator->current();

            if ($entry instanceof Entry) {
                $filtered = $this->accessControl->filterEntry(
                    $token,
                    $entry,
                );

                if ($filtered === null) {
                    $generator->next();
                    continue;
                }

                if ($filtered !== $entry && !$this->filterEvaluator->evaluate($filtered, $filter)) {
                    $generator->next();
                    continue;
                }

                $page[] = $projection->project($filtered);

                if ($sizeLimit > 0 && count($page) >= $sizeLimit) {
                    $generator->next();
                    break;
                }
            }

            $generator->next();
        }

        $generatorExhausted = !$generator->valid();
        $sizeLimitExceeded = !$generatorExhausted
            && $sizeLimit > 0
            && count($page) >= $sizeLimit;

        return new CollectedPage(
            $page,
            $generatorExhausted,
            $sizeLimitExceeded,
        );
    }

    private function projectionFor(SearchRequest $request): AttributeProjection
    {
        return AttributeProjection::forRequest(
            $request->getAttributes(),
            $request->getAttributesOnly(),
            $this->schema,
        );
    }

    /**
     * @throws OperationException
     * @throws ProtocolException
     */
    private function findOrMakePagingRequest(LdapMessageRequest $message): PagingRequest
    {
        $pagingControl = $this->getPagingControlFromMessage($message);

        if ($pagingControl->getCookie() !== '') {
            return $this->findPagingRequestOrThrow($pagingControl->getCookie());
        }

        $this->evictOldestSessionAtLimit();

        $pagingRequest = $this->makePagingRequest($message);
        $this->requestHistory->pagingRequest()->add($pagingRequest);

        return $pagingRequest;
    }

    /**
     * Unfinished sessions would otherwise retain a generator apiece for the life of the connection.
     */
    private function evictOldestSessionAtLimit(): void
    {
        $limit = $this->limits->maxPagingSessions ?? 0;
        $requests = $this->requestHistory->pagingRequest();

        if ($limit <= 0 || $requests->count() < $limit) {
            return;
        }

        $oldest = $requests->oldest();
        if ($oldest === null) {
            return;
        }

        $requests->remove($oldest);
        $this->requestHistory->removePagingGenerator($oldest->getNextCookie());
        $this->eventLogger?->record(
            ServerEvent::PagingSessionEvicted,
            [EventContext::LIMIT => $limit],
        );
    }

    /**
     * @throws OperationException
     */
    private function makePagingRequest(LdapMessageRequest $message): PagingRequest
    {
        $request = $this->getSearchRequestFromMessage($message);
        $pagingControl = $this->getPagingControlFromMessage($message);

        return new PagingRequest(
            $pagingControl,
            $request,
            $this->controlsForBackend($message),
            $this->generateCookie(),
        );
    }

    /**
     * @throws OperationException
     */
    private function findPagingRequestOrThrow(string $cookie): PagingRequest
    {
        try {
            return $this->requestHistory
                ->pagingRequest()
                ->findByNextCookie($cookie);
        } catch (ProtocolException $e) {
            throw new OperationException(
                $e->getMessage(),
                ResultCode::OPERATIONS_ERROR,
            );
        }
    }

    /**
     * @throws OperationException
     */
    /**
     * @param list<Entry> $page
     */
    private function pageHasCapacity(
        array $page,
        ?int $pageLimit,
    ): bool {
        return $pageLimit === null
            || count($page) < $pageLimit;
    }

    private function generateCookie(): string
    {
        try {
            return random_bytes(16);
        } catch (Throwable) {
            throw new OperationException(
                'Internal server error.',
                ResultCode::OPERATIONS_ERROR,
            );
        }
    }
}
