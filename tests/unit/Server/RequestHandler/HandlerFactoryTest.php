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

namespace Tests\Unit\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\HandlerFactory;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;

final class HandlerFactoryTest extends TestCase
{
    private HandlerFactory $subject;

    public function test_it_should_allow_a_request_handler_as_an_object(): void
    {
        $handler = new GenericRequestHandler();
        $this->subject = new HandlerFactory((new ServerOptions())->setRequestHandler($handler));

        self::assertSame(
            $handler,
            $this->subject->makeRequestHandler()
        );
    }

    public function test_it_should_allow_a_rootdse_handler_as_an_object(): void
    {
        $rootDseHandler = new ProxyHandler(new LdapClient());
        $this->subject = new HandlerFactory((new ServerOptions())->setRootDseHandler($rootDseHandler));;

        self::assertSame(
            $rootDseHandler,
            $this->subject->makeRootDseHandler()
        );
    }

    public function test_it_should_allow_a_null_rootdse_handler(): void
    {
        $this->subject = new HandlerFactory(
            (new ServerOptions())->setRootDseHandler(null)
        );

        self::assertNull($this->subject->makeRootDseHandler());
    }

    public function test_it_should_allow_a_paging_handler_as_an_object(): void
    {
        $pagingHandler = $this->createMock(PagingHandlerInterface::class);
        $this->subject = new HandlerFactory(
            (new ServerOptions())->setPagingHandler($pagingHandler)
        );

        self::assertSame(
            $pagingHandler,
            $this->subject->makePagingHandler()
        );
    }

    public function test_it_should_allow_a_null_paging_handler(): void
    {
        $this->subject = new HandlerFactory(
            (new ServerOptions())->setPagingHandler(null)
        );

        self::assertNull($this->subject->makePagingHandler());
    }
}
