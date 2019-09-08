<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Factory\ServerProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerRootDseHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSearchHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnbindHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerWhoAmIHandler;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PhpSpec\ObjectBehavior;

class ServerProtocolHandlerFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ServerProtocolHandlerFactory::class);
    }

    function it_should_get_a_start_tls_hanlder()
    {
        $this->get(Operations::extended(ExtendedRequest::OID_START_TLS))->shouldBeLike(new ServerStartTlsHandler());
    }

    function it_should_get_a_whoami_handler()
    {
        $this->get(Operations::whoami())->shouldBeLike(new ServerWhoAmIHandler());
    }

    function it_should_get_a_search_handler()
    {
        $this->get(Operations::list(new EqualityFilter('foo', 'bar'), 'cn=foo'))->shouldBeLike(new ServerSearchHandler());
    }

    function it_should_get_a_root_dse_handler()
    {
        $this->get(Operations::read(''))->shouldBeLike(new ServerRootDseHandler());
    }

    function it_should_get_an_unbind_handler()
    {
        $this->get(Operations::unbind())->shouldBeLike(new ServerUnbindHandler());
    }

    function it_should_get_the_dispatch_handler_for_common_requests()
    {
        $this->get(Operations::add(Entry::fromArray('cn=foo')))->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::delete('cn=foo'))->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::compare('cn=foo', 'foo', 'bar'))->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::modify('cn=foo'))->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::move('cn=foo', 'foo=bar'))->shouldBeLike(new ServerDispatchHandler());
        $this->get(Operations::rename('cn=foo', 'cn=foo'))->shouldBeLike(new ServerDispatchHandler());
    }
}
