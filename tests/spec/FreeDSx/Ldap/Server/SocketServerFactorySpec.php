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

use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\SocketServer;
use PhpSpec\Exception\Example\SkippingException;
use PhpSpec\ObjectBehavior;
use Psr\Log\LoggerInterface;

class SocketServerFactorySpec extends ObjectBehavior
{
    private $tmpUnixSocketResource;

    private string $tmpUnixSocketFilePath;

    public function let(LoggerInterface $logger): void
    {
        $this->tmpUnixSocketResource = tmpfile();
        $this->tmpUnixSocketFilePath = stream_get_meta_data($this->tmpUnixSocketResource)['uri'];

        $this->beConstructedWith(
            (new ServerOptions())
                ->setPort(3390),
            $logger,
        );
    }

    public function letGo(): void
    {
        fclose($this->tmpUnixSocketResource);
    }

    public function it_should_make_and_bind_the_socket_server(): void
    {
        $this->makeAndBind()
            ->shouldBeAnInstanceOf(SocketServer::class);
    }

    public function it_should_make_a_unix_based_socket_server(LoggerInterface $logger): void
    {
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            throw new SkippingException('Cannot construct unix based socket on Windows.');
        }
        $this->beConstructedWith(
            (new ServerOptions())
                ->setUnixSocket($this->tmpUnixSocketFilePath)
                ->setTransport('unix'),
            $logger,
        );

        $this->makeAndBind()
            ->shouldBeAnInstanceOf(SocketServer::class);
    }
}
