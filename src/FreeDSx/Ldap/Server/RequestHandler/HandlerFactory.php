<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use Throwable;

/**
 * This is used by the server protocol handler to instantiate the possible user-land LDAP handlers (ie. handlers exposed
 * in the public API options).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class HandlerFactory implements HandlerFactoryInterface
{
    /**
     * @var RequestHandlerInterface|null
     */
    private $requestHandler;

    /**
     * @var RootDseHandlerInterface|null
     */
    private $rootdseHandler;

    /**
     * @var PagingHandlerInterface|null
     */
    private $pagingHandler;

    /**
     * @var array<string, mixed>
     */
    private $options;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(array $options)
    {
        $this->options = $options;
    }

    /**
     * @inheritDoc
     */
    public function makeRequestHandler(): RequestHandlerInterface
    {
        if (!$this->requestHandler) {
            $requestHandler = !isset($this->options['request_handler'])
                ? new GenericRequestHandler()
                : $this->makeOrReturnInstanceOf(
                    'request_handler',
                    RequestHandlerInterface::class
                );
            if (!$requestHandler instanceof RequestHandlerInterface) {
                throw new RuntimeException(sprintf(
                    'Expected an instance of %s, got: %s',
                    RequestHandlerInterface::class,
                    get_class($requestHandler)
                ));
            }
            $this->requestHandler = $requestHandler;
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

        if (isset($this->options['rootdse_handler'])) {
            $handler = $this->makeOrReturnInstanceOf(
                'rootdse_handler',
                RootDseHandlerInterface::class
            );
        }

        if ($handler instanceof RootDseHandlerInterface) {
            $this->rootdseHandler = $handler;
        }

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

        $handler = null;
        if (isset($this->options['paging_handler'])) {
            $handler = $this->makeOrReturnInstanceOf(
                'paging_handler',
                PagingHandlerInterface::class
            );
        }

        if ($handler !== null && !$handler instanceof PagingHandlerInterface) {
            throw new RuntimeException(sprintf(
                'Expected an instance of %s, got: %s',
                PagingHandlerInterface::class,
                get_class($handler)
            ));
        }
        $this->pagingHandler = $handler;

        return $this->pagingHandler;
    }

    /**
     * @param string $optionName
     * @param class-string $class
     * @return object
     */
    private function makeOrReturnInstanceOf(
        string $optionName,
        string $class
    ) {
        if (!isset($this->options[$optionName])) {
            throw new RuntimeException(sprintf(
                'Option "%s" must be an instance of or fully qualified class-name implementing "%s".',
                $optionName,
                $class
            ));
        }

        $objOrString = $this->options[$optionName];
        if (!(is_object($objOrString) || is_string($objOrString))) {
            throw new RuntimeException(sprintf(
                'Option "%s" must be an instance of or fully qualified class-name implementing "%s".',
                $optionName,
                $class
            ));
        }

        if (is_object($objOrString) && is_subclass_of($objOrString, $class)) {
            return $objOrString;
        }

        if (is_string($objOrString) && is_subclass_of($objOrString, $class)) {
            try {
                return new $objOrString();
            } catch (Throwable $e) {
                throw new RuntimeException(sprintf(
                    'Unable to instantiate class "%s" for option "%s": %s',
                    $objOrString,
                    $optionName,
                    $e->getMessage()
                ), $e->getCode(), $e);
            }
        }

        throw new RuntimeException(sprintf(
            'Option "%s" must be an instance of or fully qualified class-name implementing "%s".',
            $optionName,
            $class
        ));
    }
}
