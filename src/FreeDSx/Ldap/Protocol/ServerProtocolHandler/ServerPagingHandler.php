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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\SearchContext;
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
        if (($response && $response->isComplete()) || $searchResult->getResultCode() !== ResultCode::SUCCESS) {
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
        $context = $this->makeSearchContext($searchRequest);
        $generator = $this->backend->search($context);

        [$page, $generatorExhausted] = $this->collectFromGenerator(
            $generator,
            $pagingRequest->getSize(),
            $context,
        );

        $nextCookie = $this->generateCookie();
        $pagingRequest->updateNextCookie($nextCookie);

        if ($generatorExhausted) {
            return PagingResponse::makeFinal(new Entries(...$page));
        }

        $this->requestHistory->storePagingGenerator($nextCookie, $generator);

        return PagingResponse::make(new Entries(...$page), 0);
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
            $this->requestHistory->removePagingGenerator($pagingRequest->getNextCookie());

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

        $this->requestHistory->removePagingGenerator($currentCookie);

        $searchRequest = $pagingRequest->getSearchRequest();
        $context = $this->makeSearchContext($searchRequest);

        [$page, $generatorExhausted] = $this->collectFromGenerator(
            $generator,
            $pagingRequest->getSize(),
            $context,
        );

        $nextCookie = $this->generateCookie();
        $pagingRequest->updateNextCookie($nextCookie);

        if ($generatorExhausted) {
            return PagingResponse::makeFinal(new Entries(...$page));
        }

        $this->requestHistory->storePagingGenerator($nextCookie, $generator);

        return PagingResponse::make(new Entries(...$page), 0);
    }

    /**
     * Advances the generator, collecting up to $size entries that pass the filter.
     * Returns the collected entries and whether the generator is exhausted.
     *
     * @return array{Entry[], bool}
     */
    private function collectFromGenerator(
        Generator $generator,
        int $size,
        SearchContext $context,
    ): array {
        $page = [];
        $limit = $size > 0 ? $size : PHP_INT_MAX;

        while ($generator->valid() && count($page) < $limit) {
            $entry = $generator->current();

            if ($entry instanceof Entry && $this->filterEvaluator->evaluate($entry, $context->filter)) {
                $page[] = $this->applyAttributeFilter($entry, $context->attributes, $context->typesOnly);
            }

            $generator->next();
        }

        return [$page, !$generator->valid()];
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

        $filteredControls = array_filter(
            $message->controls()->toArray(),
            static function (Control $control): bool {
                return $control->getTypeOid() !== Control::OID_PAGING;
            }
        );

        return new PagingRequest(
            $pagingControl,
            $request,
            new ControlBag(...$filteredControls),
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
