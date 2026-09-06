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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Paging\CollectedPage;
use FreeDSx\Ldap\Server\Paging\PageFiller;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingRequestComparator;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\TokenInterface;
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
        private readonly ReadBackendInterface $backend,
        private readonly AccessControlInterface $accessControl,
        private readonly RequestHistory $requestHistory,
        private readonly Schema $schema,
        private readonly PageFiller $pageFiller,
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

        $sortControl = $this->sortingControl($message);
        $sortResponse = $this->sortingResponseControl(
            $sortControl,
            $this->schema,
        );

        $response = null;
        $controls = [];
        $entriesReturned = 0;
        $failure = null;
        try {
            $this->assertBaseDnProvided($searchRequest);
            $this->assertSortIsSatisfiable(
                $sortControl,
                $sortResponse,
            );

            $response = $this->handlePaging(
                $pagingRequest,
                $message,
                $token,
            );
            if ($response->isSizeLimitExceeded()) {
                $searchResult = SearchResult::makeSizeLimitResult($response->getEntries());
                $controls[] = new PagingControl(0, '');
            } else {
                $searchResult = SearchResult::makeSuccessResult($response->getEntries());
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
         * remove the paging request and discard the cursor.
         */
        if (($response && $response->isComplete()) || $searchResult->getState()->resultCode !== ResultCode::SUCCESS) {
            $this->requestHistory->pagingRequest()->remove($pagingRequest);
            $this->requestHistory->removePagingCursor($pagingRequest->getNextCookie());
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
        $collected = $this->pageFiller->fill(
            $pagingRequest,
            $token,
            null,
        );

        return $this->buildPagingResponse(
            $collected,
            $pagingRequest,
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
        $resumeFrom = $this->requestHistory->getPagingCursor($currentCookie);

        if ($resumeFrom === null) {
            throw new OperationException(
                'The paging session could not be resumed.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        $this->requestHistory->removePagingCursor($currentCookie);

        $collected = $this->pageFiller->fill(
            $pagingRequest,
            $token,
            $resumeFrom,
        );

        return $this->buildPagingResponse(
            $collected,
            $pagingRequest,
        );
    }

    /**
     * @throws OperationException
     */
    private function buildPagingResponse(
        CollectedPage $collected,
        PagingRequest $pagingRequest,
    ): PagingResponse {
        if ($collected->isSizeLimitExceeded) {
            return PagingResponse::makeSizeLimitExceeded(new Entries(...$collected->entries));
        }

        $nextCookie = $this->generateCookie();
        $pagingRequest->updateNextCookie($nextCookie);

        // Without a position there is nothing to resume from, so the result has to be treated as finished.
        if ($collected->isResultExhausted || $collected->cursor === null) {
            return PagingResponse::makeFinal(new Entries(...$collected->entries));
        }

        $this->requestHistory->storePagingCursor(
            $nextCookie,
            $collected->cursor,
        );

        return PagingResponse::make(
            new Entries(...$collected->entries),
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
        $limit = $this->limits->maxPagingSessions() ?? 0;
        $requests = $this->requestHistory->pagingRequest();

        if ($limit <= 0 || $requests->count() < $limit) {
            return;
        }

        $oldest = $requests->oldest();
        if ($oldest === null) {
            return;
        }

        $requests->remove($oldest);
        $this->requestHistory->removePagingCursor($oldest->getNextCookie());
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
            // An aged-out session leaves no record, so a resumed one and an invented one answer alike.
            throw new OperationException(
                $e->getMessage(),
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }
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
