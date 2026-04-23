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
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingRequestComparator;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
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

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly LdapBackendInterface $backend,
        private readonly FilterEvaluatorInterface $filterEvaluator,
        private readonly RequestHistory $requestHistory,
        private readonly PagingRequestComparator $requestComparator = new PagingRequestComparator(),
    ) {
    }

    /**
     * @inheritDoc
     * @throws ProtocolException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token
    ): void {
        $pagingRequest = $this->findOrMakePagingRequest($message);
        $searchRequest = $this->getSearchRequestFromMessage($message);

        $response = null;
        $controls = [];
        try {
            $response = $this->handlePaging($pagingRequest, $message);
            if ($response->isSizeLimitExceeded()) {
                $searchResult = SearchResult::makeSizeLimitResult(
                    $response->getEntries(),
                    (string) $searchRequest->getBaseDn(),
                );
                $controls[] = new PagingControl(0, '');
            } else {
                $searchResult = SearchResult::makeSuccessResult(
                    $response->getEntries(),
                    (string) $searchRequest->getBaseDn()
                );
                $controls[] = new PagingControl(
                    $response->getRemaining(),
                    $response->isComplete()
                        ? ''
                        : $pagingRequest->getNextCookie()
                );
            }
        } catch (OperationException $e) {
            $searchResult = SearchResult::makeErrorResult(
                $e->getCode(),
                (string) $searchRequest->getBaseDn(),
                $e->getMessage()
            );
            $controls[] = new PagingControl(0, '');
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

        $this->sendEntriesToClient(
            $searchResult,
            $message,
            $this->queue,
            ...$controls
        );
    }

    /**
     * @throws OperationException
     */
    private function handlePaging(
        PagingRequest $pagingRequest,
        LdapMessageRequest $message
    ): PagingResponse {
        if (!$pagingRequest->isPagingStart()) {
            return $this->handleExistingCookie($pagingRequest, $message);
        }

        return $this->handlePagingStart($pagingRequest);
    }

    /**
     * @throws OperationException
     */
    private function handlePagingStart(PagingRequest $pagingRequest): PagingResponse
    {
        $searchRequest = $pagingRequest->getSearchRequest();
        $this->assertBaseDnProvided($searchRequest);

        $result = $this->backend->search(
            $searchRequest,
            $pagingRequest->controls(),
        );
        $generator = $result->entries;
        $isPreFiltered = $result->isPreFiltered;

        $collected = $this->collectFromGenerator(
            $generator,
            $pagingRequest->getSize(),
            $searchRequest,
            0,
            $isPreFiltered,
        );

        return $this->buildPagingResponse(
            $collected,
            $pagingRequest,
            $generator,
            $isPreFiltered,
        );
    }

    /**
     * @throws OperationException
     */
    private function handleExistingCookie(
        PagingRequest $pagingRequest,
        LdapMessageRequest $message
    ): PagingResponse {
        $newPagingRequest = $this->makePagingRequest($message);

        if (!$this->requestComparator->compare($pagingRequest, $newPagingRequest)) {
            throw new OperationException(
                'The search request and controls must be identical between paging requests.',
                ResultCode::OPERATIONS_ERROR
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
                ResultCode::OPERATIONS_ERROR
            );
        }

        $isPreFiltered = $this->requestHistory->getPagingGeneratorIsPreFiltered($currentCookie);
        $this->requestHistory->removePagingGenerator($currentCookie);

        $collected = $this->collectFromGenerator(
            $generator,
            $pagingRequest->getSize(),
            $pagingRequest->getSearchRequest(),
            $pagingRequest->getTotalSent(),
            $isPreFiltered,
        );

        return $this->buildPagingResponse(
            $collected,
            $pagingRequest,
            $generator,
            $isPreFiltered
        );
    }

    /**
     * @throws OperationException
     */
    private function buildPagingResponse(
        CollectedPage $collected,
        PagingRequest $pagingRequest,
        Generator $generator,
        bool $isPreFiltered,
    ): PagingResponse {
        if ($collected->isSizeLimitExceeded) {
            return PagingResponse::makeSizeLimitExceeded(new Entries(...$collected->entries));
        }

        $nextCookie = $this->generateCookie();
        $pagingRequest->updateNextCookie($nextCookie);

        if ($collected->isGeneratorExhausted) {
            return PagingResponse::makeFinal(new Entries(...$collected->entries));
        }

        $pagingRequest->incrementTotalSent(count($collected->entries));
        $this->requestHistory->storePagingGenerator(
            $nextCookie,
            $generator,
            $isPreFiltered,
        );

        return PagingResponse::make(
            new Entries(...$collected->entries)
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
        int $totalAlreadySent,
        bool $isPreFiltered = false,
    ): CollectedPage {
        $page = [];
        $pageLimit = $pageSize > 0 ? $pageSize : PHP_INT_MAX;
        $sizeLimit = $request->getSizeLimit();
        $filter = $request->getFilter();

        while ($generator->valid() && count($page) < $pageLimit) {
            $entry = $generator->current();

            if ($entry instanceof Entry && ($isPreFiltered || $this->filterEvaluator->evaluate($entry, $filter))) {
                $page[] = $this->applyAttributeFilter(
                    $entry,
                    $request->getAttributes(),
                    $request->getAttributesOnly(),
                );

                if ($sizeLimit > 0 && ($totalAlreadySent + count($page)) >= $sizeLimit) {
                    $generator->next();
                    break;
                }
            }

            $generator->next();
        }

        $generatorExhausted = !$generator->valid();
        $sizeLimitExceeded = !$generatorExhausted
            && $sizeLimit > 0
            && ($totalAlreadySent + count($page)) >= $sizeLimit;

        return new CollectedPage(
            $page,
            $generatorExhausted,
            $sizeLimitExceeded,
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

        $pagingRequest = $this->makePagingRequest($message);
        $this->requestHistory->pagingRequest()->add($pagingRequest);

        return $pagingRequest;
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
            $this->nonPagingControls($message),
            $this->generateCookie()
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
                ResultCode::OPERATIONS_ERROR
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function generateCookie(): string
    {
        try {
            return random_bytes(16);
        } catch (Throwable) {
            throw new OperationException(
                'Internal server error.',
                ResultCode::OPERATIONS_ERROR
            );
        }
    }
}
