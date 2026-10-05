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

use FreeDSx\Ldap\Exception\RuntimeException as LdapRuntimeException;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Server\SocketServerFactory;
use FreeDSx\Ldap\Server\TlsVersion;
use FreeDSx\Socket\Timeout\BlockingSelectEnforcer;
use FreeDSx\Socket\Timeout\SwooleTimerEnforcer;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\RequiresOperatingSystemTrait;

final class SocketServerFactoryTest extends TestCase
{
    use RequiresOperatingSystemTrait;

    /**
     * @var resource
     */
    private $tmpUnixSocketResource;

    private string $tmpUnixSocketFilePath;

    private SocketServerFactory $subject;

    protected function setUp(): void
    {
        $this->tmpUnixSocketResource = $this->makeTempFile();
        $this->tmpUnixSocketFilePath = stream_get_meta_data($this->tmpUnixSocketResource)['uri'] ?? throw new RuntimeException('Unable to get temp file path for unix socket.');

        $this->subject = new SocketServerFactory(
            NetworkConfig::withPort(3390),
            RunnerMode::Pcntl,
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
            (new NetworkConfig())
                ->setPort(3391)
                ->setWriteTimeout(45),
            RunnerMode::Pcntl,
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
            (new NetworkConfig())
                ->setPort(3392)
                ->setWriteTimeout(45),
            RunnerMode::Swoole,
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
            (new NetworkConfig())
                ->setPort(3393)
                ->setMinTlsVersion(TlsVersion::Tls1_3)
                ->setSslCiphers('ECDHE-RSA-AES128-GCM-SHA256')
                ->setSslValidateCert(true)
                ->setSslAllowSelfSigned(true)
                ->setSslCaCert('/path/to/ca.pem'),
            RunnerMode::Pcntl,
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

    public function test_it_defers_the_tls_handshake_to_the_connection_handler_for_the_pcntl_runner(): void
    {
        $subject = new SocketServerFactory(
            (new NetworkConfig())
                ->setPort(3394)
                ->setUseSsl(true),
            RunnerMode::Pcntl,
        );

        self::assertTrue($subject->isTlsHandshakeDeferred());
        self::assertFalse($subject->makeAndBind()->getOptions()->isUseSsl());
    }

    public function test_it_defers_the_tls_handshake_to_the_connection_handler_for_the_swoole_runner(): void
    {
        $subject = new SocketServerFactory(
            (new NetworkConfig())
                ->setPort(3395)
                ->setUseSsl(true),
            RunnerMode::Swoole,
        );

        self::assertTrue($subject->isTlsHandshakeDeferred());
        self::assertFalse($subject->makeAndBind()->getOptions()->isUseSsl());
    }

    public function test_it_has_no_tls_handshake_to_defer_without_ssl(): void
    {
        self::assertFalse($this->subject->isTlsHandshakeDeferred());
    }

    public function test_it_should_make_a_unix_based_socket_server(): void
    {
        $this->requireUnix('Cannot construct unix based socket on Windows.');
        self::expectNotToPerformAssertions();

        $this->subject = new SocketServerFactory(
            (new NetworkConfig())
                ->setUnixSocket($this->tmpUnixSocketFilePath)
                ->setTransport('unix'),
            RunnerMode::Pcntl,
        );

        $this->subject->makeAndBind();
    }

    public function test_an_existing_socket_that_is_not_writeable_is_recorded_and_refused(): void
    {
        $this->requireUnix('Cannot construct unix based socket on Windows.');
        chmod(
            $this->tmpUnixSocketFilePath,
            0444,
        );
        clearstatcache();
        if (is_writable($this->tmpUnixSocketFilePath)) {
            $this->markTestSkipped('The file stays writeable for this user.');
        }

        $logger = $this->createMock(LoggerInterface::class);
        $logger
            ->expects(self::once())
            ->method('log')
            ->with(
                LogLevel::ERROR,
                self::anything(),
                self::callback(fn(array $context): bool => $context[EventContext::EVENT] === ServerEvent::SocketUnusable->value
                    && $context['socket'] === $this->tmpUnixSocketFilePath
                    && $context[EventContext::REASON] === 'not_writeable'),
            );
        $subject = new SocketServerFactory(
            (new NetworkConfig())
                ->setUnixSocket($this->tmpUnixSocketFilePath)
                ->setTransport('unix'),
            RunnerMode::Pcntl,
            new EventLogger(
                $logger,
                EventLogPolicy::default(),
            ),
        );

        $this->expectException(LdapRuntimeException::class);

        $subject->makeAndBind();
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
