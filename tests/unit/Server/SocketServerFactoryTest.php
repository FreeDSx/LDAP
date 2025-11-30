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

namespace Tests\Unit\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\SocketServer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use RuntimeException;

final class SocketServerFactoryTest extends TestCase
{
    /**
     * @var resource
     */
    private $tmpUnixSocketResource;

    private string $tmpUnixSocketFilePath;

    private SocketServerFactory $subject;

    private LoggerInterface&MockObject $mockLogger;

    protected function setUp(): void
    {
        $this->tmpUnixSocketResource = $this->makeTempFile();;
        $this->tmpUnixSocketFilePath = stream_get_meta_data($this->tmpUnixSocketResource)['uri'];
        $this->mockLogger = $this->createMock(LoggerInterface::class);

        $this->subject = new SocketServerFactory(
            (new ServerOptions())
                ->setPort(3390),
            $this->mockLogger,
        );
    }

    protected function tearDown(): void
    {
        fclose($this->tmpUnixSocketResource);
    }

    public function test_it_should_make_and_bind_the_socket_server(): void
    {
        self::assertInstanceOf(
            SocketServer::class,
            $this->subject->makeAndBind(),
        );
    }

    public function test_it_should_make_a_unix_based_socket_server(): void
    {
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            $this->markTestSkipped('Cannot construct unix based socket on Windows.');
        }

        $this->subject = new SocketServerFactory(
            (new ServerOptions())
                ->setUnixSocket($this->tmpUnixSocketFilePath)
                ->setTransport('unix'),
            $this->mockLogger,
        );

        self::assertInstanceOf(
            SocketServer::class,
            $this->subject->makeAndBind(),
        );
    }

    /**
     * @return resource
     */
    private function makeTempFile()
    {
        $tempFile = tmpfile();

        if ($tempFile === false) {
            throw new RuntimeException('Unable to create temporary file.');
        }

        return $tempFile;
    }
}
