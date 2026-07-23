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

use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\Server\TlsVersion;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Timeout\BlockingSelectEnforcer;
use FreeDSx\Socket\Timeout\SwooleTimerEnforcer;
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
        $this->tmpUnixSocketResource = $this->makeTempFile();
        ;
        $this->tmpUnixSocketFilePath = stream_get_meta_data($this->tmpUnixSocketResource)['uri'] ?? throw new RuntimeException('Unable to get temp file path for unix socket.');
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
        self::expectNotToPerformAssertions();

        $this->subject->makeAndBind();
    }

    public function test_it_uses_the_blocking_select_enforcer_for_the_pcntl_runner(): void
    {
        $subject = new SocketServerFactory(
            (new ServerOptions())
                ->setPort(3391)
                ->setWriteTimeout(45),
            $this->mockLogger,
        );

        $options = $subject->makeAndBind()->getOptions();

        self::assertSame(
            45,
            $options->getWriteTimeout(),
        );
        self::assertInstanceOf(
            BlockingSelectEnforcer::class,
            $options->getWriteTimeoutEnforcer(),
        );
    }

    public function test_it_uses_the_swoole_timer_enforcer_for_the_swoole_runner(): void
    {
        $subject = new SocketServerFactory(
            (new ServerOptions())
                ->setPort(3392)
                ->setWriteTimeout(45)
                ->setRunner(RunnerMode::Swoole),
            $this->mockLogger,
        );

        $options = $subject->makeAndBind()->getOptions();

        self::assertSame(
            45,
            $options->getWriteTimeout(),
        );
        self::assertInstanceOf(
            SwooleTimerEnforcer::class,
            $options->getWriteTimeoutEnforcer(),
        );
    }

    public function test_it_flows_the_tls_settings_to_the_socket_server(): void
    {
        $subject = new SocketServerFactory(
            (new ServerOptions())
                ->setPort(3393)
                ->setMinTlsVersion(TlsVersion::Tls1_3)
                ->setSslCiphers('ECDHE-RSA-AES128-GCM-SHA256')
                ->setSslValidateCert(true)
                ->setSslAllowSelfSigned(true)
                ->setSslCaCert('/path/to/ca.pem'),
            $this->mockLogger,
        );

        $options = $subject->makeAndBind()->getOptions();

        self::assertSame(
            TlsVersion::Tls1_3->toServerCryptoMethod(),
            $options->getSslCryptoMethod(),
        );
        self::assertSame(
            'ECDHE-RSA-AES128-GCM-SHA256',
            $options->getSslCiphers(),
        );
        self::assertTrue($options->isSslValidateCert());
        self::assertTrue($options->getSslAllowSelfSigned());
        self::assertSame(
            '/path/to/ca.pem',
            $options->getSslCaCert(),
        );
    }

    public function test_it_should_make_a_unix_based_socket_server(): void
    {
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            $this->markTestSkipped('Cannot construct unix based socket on Windows.');
        }
        self::expectNotToPerformAssertions();

        $this->subject = new SocketServerFactory(
            (new ServerOptions())
                ->setUnixSocket($this->tmpUnixSocketFilePath)
                ->setTransport('unix'),
            $this->mockLogger,
        );

        $this->subject->makeAndBind();
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
