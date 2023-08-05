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

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * This is used by the server protocol handler to instantiate the possible user-land LDAP handlers (ie. handlers exposed
 * in the public API options).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class HandlerFactory implements HandlerFactoryInterface
{
    private ?RequestHandlerInterface $requestHandler = null;

    private ?RootDseHandlerInterface $rootdseHandler = null;

    private ?PagingHandlerInterface $pagingHandler = null;

    public function __construct(private readonly ServerOptions $options)
    {
    }

    /**
     * @inheritDoc
     */
    public function makeRequestHandler(): RequestHandlerInterface
    {
        if (!$this->requestHandler) {
            $this->requestHandler = $this->options->getRequestHandler() ?? new GenericRequestHandler();
        }

        return $this->requestHandler;
    }

    /**
     * @inheritDoc
     */
    public function makeRootDseHandler(): ?RootDseHandlerInterface
    {
        if ($this->rootdseHandler) {
            return $this->rootdseHandler;
        }
        $handler = $this->makeRequestHandler();
        $this->rootdseHandler = $handler instanceof RootDseHandlerInterface
            ? $handler
            : null;

        if ($this->rootdseHandler) {
            return $this->rootdseHandler;
        }
        $this->rootdseHandler = $this->options->getRootDseHandler();

        return $this->rootdseHandler;
    }

    /**
     * @inheritDoc
     */
    public function makePagingHandler(): ?PagingHandlerInterface
    {
        if ($this->pagingHandler) {
            return $this->pagingHandler;
        }
        $this->pagingHandler = $this->options->getPagingHandler();

        return $this->pagingHandler;
    }
}
