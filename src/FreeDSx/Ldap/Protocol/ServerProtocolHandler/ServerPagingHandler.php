<?php

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

    /**
     * @var PagingHandlerInterface
     */
    private $pagingHandler;

    /**
     * @var RequestHistory
     */
    private $requestHistory;

    /**
     * @var PagingRequestComparator
     */
    private $requestComparator;

    public function __construct(
        PagingHandlerInterface $pagingHandler,
        RequestHistory $requestHistory,
        ?PagingRequestComparator $requestComparator = null
    ) {
        $this->pagingHandler = $pagingHandler;
        $this->requestHistory = $requestHistory;
        $this->requestComparator = $requestComparator ?? new PagingRequestComparator();
    }

    /**
     * @inheritDoc
     * @throws ProtocolException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
        RequestHandlerInterface $dispatcher,
        ServerQueue $queue,
        array $options
    ): void {
        $context = new RequestContext(
            $message->controls(),
            $token
        );
        $pagingRequest = $this->findOrMakePagingRequest($message);

        $response = $this->handlePaging(
            $context,
            $pagingRequest,
            $message
        );

        $pagingRequest->markProcessed();

        if ($response->isComplete()) {
            $this->requestHistory->pagingRequest()
                ->remove($pagingRequest);
            $this->pagingHandler->remove(
                $pagingRequest,
                $context
            );
        }

        $this->sendEntriesToClient(
            $response->getEntries(),
            $message,
            $queue,
            new PagingControl(
                $response->getRemaining(),
                $response->isComplete() ? '' : $pagingRequest->getNextCookie()
            )
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
     * @return string
     * @throws OperationException
     */
    private function generateCookie(): string
    {
        try {
            return random_bytes(16);
        } catch (Throwable $e) {
            throw new OperationException(
                'Internal server error.',
                ResultCode::OPERATIONS_ERROR
            );
        }
    }

    /**
     * @param LdapMessageRequest $message
     * @return PagingRequest
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
     * @param LdapMessageRequest $message
     * @return PagingRequest
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
     * @param string $cookie
     * @return PagingRequest
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
     * @param PagingRequest $pagingRequest
     * @param RequestContext $context
     * @return PagingResponse
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
