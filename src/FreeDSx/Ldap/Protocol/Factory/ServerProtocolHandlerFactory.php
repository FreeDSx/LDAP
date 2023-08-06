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

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\Server\RequestHistory;
use FreeDSx\Ldap\ServerOptions;

/**
 * Determines the correct handler for the request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerProtocolHandlerFactory
{
    public function __construct(
        private readonly HandlerFactoryInterface $handlerFactory,
        private readonly ServerOptions $options,
        private readonly RequestHistory $requestHistory,
        private readonly ServerQueue $queue,
    ) {
    }

    public function get(
        RequestInterface $request,
        ControlBag $controls
    ): ServerProtocolHandlerInterface {
        if ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_WHOAMI) {
            return new ServerProtocolHandler\ServerWhoAmIHandler($this->queue);
        } elseif ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS) {
            return new ServerProtocolHandler\ServerStartTlsHandler(
                options: $this->options,
                queue: $this->queue,
            );
        } elseif ($this->isRootDseSearch($request)) {
            return $this->getRootDseHandler();
        } elseif ($this->isPagingSearch($request, $controls)) {
            return $this->getPagingHandler();
        } elseif ($request instanceof SearchRequest) {
            return new ServerProtocolHandler\ServerSearchHandler($this->queue);
        } elseif ($request instanceof UnbindRequest) {
            return new ServerProtocolHandler\ServerUnbindHandler($this->queue);
        } else {
            return new ServerProtocolHandler\ServerDispatchHandler($this->queue);
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

        return new ServerProtocolHandler\ServerRootDseHandler(
            options: $this->options,
            queue: $this->queue,
            rootDseHandler: $rootDseHandler,
        );
    }

    private function getPagingHandler(): ServerProtocolHandlerInterface
    {
        $pagingHandler = $this->handlerFactory->makePagingHandler();

        if (!$pagingHandler) {
            return new ServerProtocolHandler\ServerPagingUnsupportedHandler($this->queue);
        }

        return new ServerProtocolHandler\ServerPagingHandler(
            queue: $this->queue,
            pagingHandler: $pagingHandler,
            requestHistory: $this->requestHistory,
        );
    }
}
