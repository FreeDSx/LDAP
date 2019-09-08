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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Protocol\Factory\ServerBindHandlerFactory;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerAnonBindHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerBindHandler;
use PhpSpec\ObjectBehavior;

class ServerBindHandlerFactorySpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType(ServerBindHandlerFactory::class);
    }

    public function it_should_get_an_anon_bind_handler()
    {
        $this->get(new AnonBindRequest())->shouldBeLike(new ServerAnonBindHandler());
    }

    public function it_should_get_a_simple_bind_handler()
    {
        $this->get(new SimpleBindRequest('foo', 'bar'))->shouldBeLike(new ServerBindHandler());
    }

    public function it_should_throw_an_exception_on_an_unknown_bind_type(BindRequest $request)
    {
        $this->shouldThrow(OperationException::class)->during('get', [$request]);
    }
}
