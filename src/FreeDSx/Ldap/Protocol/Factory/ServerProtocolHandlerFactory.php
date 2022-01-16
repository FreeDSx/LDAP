<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\RequestHistory;

/**
 * Determines the correct handler for the request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerProtocolHandlerFactory
{
    /**
     * @var HandlerFactoryInterface
     */
    private $handlerFactory;

    /**
     * @var RequestHistory
     */
    private $requestHistory;

    public function __construct(
        HandlerFactoryInterface $handlerFactory,
        RequestHistory $requestHistory
    ) {
        $this->handlerFactory = $handlerFactory;
        $this->requestHistory = $requestHistory;
    }

    public function get(
        RequestInterface $request,
        ControlBag $controls
    ): ServerProtocolHandlerInterface {
        if ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_WHOAMI) {
            return new ServerProtocolHandler\ServerWhoAmIHandler();
        } elseif ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS) {
            return new ServerProtocolHandler\ServerStartTlsHandler();
        } elseif ($this->isRootDseSearch($request)) {
            return $this->getRootDseHandler();
        } elseif ($this->isPagingSearch($request, $controls)) {
            return $this->getPagingHandler();
        } elseif ($request instanceof SearchRequest) {
            return new ServerProtocolHandler\ServerSearchHandler();
        } elseif ($request instanceof UnbindRequest) {
            return new ServerProtocolHandler\ServerUnbindHandler();
        } else {
            return new ServerProtocolHandler\ServerDispatchHandler();
        }
    }

    private function isRootDseSearch(RequestInterface $request): bool
    {
        if (!$request instanceof SearchRequest) {
            return false;
        }

        return $request->getScope() === SearchRequest::SCOPE_BASE_OBJECT
                && ((string)$request->getBaseDn() === '');
    }

    private function isPagingSearch(
        RequestInterface $request,
        ControlBag $controls
    ): bool {
        return $request instanceof SearchRequest
            && $controls->has(Control::OID_PAGING);
    }

    private function getRootDseHandler(): ServerProtocolHandler\ServerRootDseHandler
    {
        $rootDseHandler = $this->handlerFactory->makeRootDseHandler();

        return new ServerProtocolHandler\ServerRootDseHandler($rootDseHandler);
    }

    private function getPagingHandler(): ServerProtocolHandlerInterface
    {
        $pagingHandler = $this->handlerFactory->makePagingHandler();

        if (!$pagingHandler) {
            return new ServerProtocolHandler\ServerPagingUnsupportedHandler();
        }

        return new ServerProtocolHandler\ServerPagingHandler(
            $pagingHandler,
            $this->requestHistory
        );
    }
}
