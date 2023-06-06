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

namespace spec\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\Server\RequestHandler\ProxyPagingHandler;
use FreeDSx\Ldap\ServerOptions;
use PhpSpec\ObjectBehavior;

class HandlerFactorySpec extends ObjectBehavior
{
    public function it_should_allow_a_request_handler_as_an_object(): void
    {
        $handler = new GenericRequestHandler();
        $this->beConstructedWith(
            (new ServerOptions())->setRequestHandler($handler)
        );

        $this->makeRequestHandler()->shouldBeEqualTo($handler);
    }

    public function it_should_allow_a_rootdse_handler_as_an_object(): void
    {
        $rootDseHandler = new ProxyHandler(new LdapClient());
        $this->beConstructedWith(
            (new ServerOptions())->setRootDseHandler($rootDseHandler)
        );

        $this->makeRootDseHandler()->shouldBeEqualTo($rootDseHandler);
    }

    public function it_should_allow_a_null_rootdse_handler(): void
    {
        $this->beConstructedWith(
            (new ServerOptions())->setRootDseHandler(null)
        );

        $this->makeRootDseHandler()->shouldBeNull();
    }

    public function it_should_allow_a_paging_handler_as_an_object(PagingHandlerInterface $pagingHandler): void
    {
        $pagingHandler = new ProxyPagingHandler(new LdapClient());
        $this->beConstructedWith(
            (new ServerOptions())->setPagingHandler($pagingHandler)
        );

        $this->makePagingHandler()->shouldBeEqualTo($pagingHandler);
    }

    public function it_should_allow_a_null_paging_handler(): void
    {
        $this->beConstructedWith(
            (new ServerOptions())->setPagingHandler(null)
        );

        $this->makePagingHandler()->shouldBeNull();
    }
}
