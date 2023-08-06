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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingRequestComparator;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Throwable;

/**
 * Handles paging search request logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerPagingHandler implements ServerProtocolHandlerInterface
{
    use ServerSearchTrait;

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly PagingHandlerInterface $pagingHandler,
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
        TokenInterface $token,
        RequestHandlerInterface $dispatcher
    ): void {
        $context = new RequestContext(
            $message->controls(),
            $token
        );
        $pagingRequest = $this->findOrMakePagingRequest($message);
        $searchRequest = $this->getSearchRequestFromMessage($message);

        $response = null;
        $controls = [];
        try {
            $response = $this->handlePaging(
                $context,
                $pagingRequest,
                $message
            );
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
            $controls[] = new PagingControl(
                0,
                ''
            );
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
         * If a search result is anything other than success, we remove the paging request.
         */
        if (($response && $response->isComplete()) || $searchResult->getResultCode() !== ResultCode::SUCCESS) {
            $this->requestHistory->pagingRequest()
                ->remove($pagingRequest);
            $this->pagingHandler->remove(
                $pagingRequest,
                $context
            );
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
        RequestContext $context,
        PagingRequest $pagingRequest,
        LdapMessageRequest $message
    ): PagingResponse {
        if (!$pagingRequest->isPagingStart()) {
            return $this->handleExistingCookie(
                $pagingRequest,
                $context,
                $message
            );
        } else {
            return $this->handlePagingStart(
                $pagingRequest,
                $context
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function handleExistingCookie(
        PagingRequest $pagingRequest,
        RequestContext $context,
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
            $response = PagingResponse::makeFinal(new Entries());
        } else {
            $response = $this->pagingHandler->page(
                $pagingRequest,
                $context
            );
            $pagingRequest->updateNextCookie($this->generateCookie());
        }

        return $response;
    }

    /**
     * @todo It would be useful to prefix these by a unique client ID or something else somewhat identifiable.
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
            function (Control $control) {
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
    private function handlePagingStart(
        PagingRequest $pagingRequest,
        RequestContext $context
    ): PagingResponse {
        $response = $this->pagingHandler->page(
            $pagingRequest,
            $context
        );
        $pagingRequest->updateNextCookie($this->generateCookie());

        return $response;
    }
}
