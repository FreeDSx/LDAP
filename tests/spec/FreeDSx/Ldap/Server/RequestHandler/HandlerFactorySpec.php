<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace spec\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use PhpSpec\ObjectBehavior;

class HandlerFactorySpec extends ObjectBehavior
{
    public function it_should_allow_a_request_handler_as_an_object()
    {
        $handler = new GenericRequestHandler();
        $this->beConstructedWith([
            'request_handler' => $handler,
        ]);

        $this->makeRequestHandler()->shouldBeEqualTo($handler);
    }

    public function it_should_only_allow_a_request_handler_implementing_request_handler_interface()
    {
        $this->beConstructedWith([
            'request_handler' => new Entry('foo'),
        ]);

        $this->shouldThrow(RuntimeException::class)->during('makeRequestHandler');
    }

    public function it_should_allow_a_request_handler_as_a_string_implementing_request_handler_interface()
    {
        $this->beConstructedWith([
            'request_handler' => ProxyRequestHandler::class,
        ]);

        $this->shouldNotThrow(RuntimeException::class)->during('makeRequestHandler');
    }

    public function it_should_allow_a_rootdse_handler_as_an_object(RootDseHandlerInterface $rootDseHandler)
    {
        $this->beConstructedWith([
            'rootdse_handler' => $rootDseHandler,
        ]);

        $this->makeRootDseHandler()->shouldBeEqualTo($rootDseHandler);
    }

    public function it_should_only_allow_a_rootdse_handler_implementing_rootdse_handler_interface()
    {
        $this->beConstructedWith([
            'rootdse_handler' => new Entry('foo'),
        ]);

        $this->shouldThrow(RuntimeException::class)->during('makeRootDseHandler');
    }

    public function it_should_allow_a_rootdse_handler_as_a_string_implementing_rootdse_handler_interface()
    {
        $handler = new class implements RootDseHandlerInterface {
            public function rootDse(RequestContext $context, SearchRequest $request, Entry $rootDse): Entry
            {
                return new Entry('');
            }
        };

        $this->beConstructedWith([
            'rootdse_handler' => get_class($handler),
        ]);

        $this->shouldNotThrow(RuntimeException::class)->during('makeRootDseHandler');
    }
}
