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

namespace spec\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Server\HandlerFactoryInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;
use PhpSpec\ObjectBehavior;

class ServerProtocolFactorySpec extends ObjectBehavior
{
    public function let(
        HandlerFactoryInterface $handlerFactory,
        ServerAuthorization $serverAuthorization,
    ): void {
        $this->beConstructedWith(
            $handlerFactory,
            new ServerOptions(),
            $serverAuthorization,
        );
    }

    public function it_should_malke_a_ServerProtocolInstance(Socket $socket): void
    {
        $this->make($socket)
            ->shouldBeAnInstanceOf(ServerProtocolHandler::class);
    }
}
