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

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;
use FreeDSx\Ldap\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class LdapServerTest extends TestCase
{
    private LdapServer $subject;

    private ServerOptions $options;

    private ServerRunnerInterface&MockObject $mockServerRunner;

    protected function setUp(): void
    {
        $this->mockServerRunner = $this->createMock(ServerRunnerInterface::class);

        $this->options = (new ServerOptions())
            ->setPort(33389)
            ->setServerRunner($this->mockServerRunner);

        $this->subject = new LdapServer($this->options);
    }

    public function test_it_should_run_the_server(): void
    {
        $this->mockServerRunner
            ->expects(self::once())
            ->method('run');

        $this->subject->run();
    }

    public function test_it_should_use_the_backend_specified(): void
    {
        $backend = $this->createMock(LdapBackendInterface::class);

        $this->subject->useBackend($backend);

        self::assertSame(
            $backend,
            $this->subject->getOptions()->getBackend()
        );
    }

    public function test_it_should_use_the_rootdse_handler_specified(): void
    {
        $rootDseHandler = $this->createMock(RootDseHandlerInterface::class);

        $this->subject->useRootDseHandler($rootDseHandler);

        self::assertSame(
            $rootDseHandler,
            $this->subject->getOptions()->getRootDseHandler()
        );
    }

    public function test_it_should_use_the_logger_specified(): void
    {
        $logger = $this->createMock(LoggerInterface::class);

        $this->subject->useLogger($logger);

        self::assertSame(
            $logger,
            $this->subject->getOptions()->getLogger()
        );
    }

    public function test_it_should_get_the_default_options(): void
    {
        self::assertEquals(
            [
                'ip' => '0.0.0.0',
                'port' => 33389,
                'unix_socket' => '/var/run/ldap.socket',
                'transport' => 'tcp',
                'idle_timeout' => 600,
                'require_authentication' => true,
                'allow_anonymous' => false,
                'backend' => null,
                'rootdse_handler' => null,
                'logger' => null,
                'use_ssl' => false,
                'ssl_cert' => null,
                'ssl_cert_key' => null,
                'ssl_cert_passphrase' => null,
                'dse_alt_server' => null,
                'dse_naming_contexts' => [
                    'dc=FreeDSx,dc=local',
                ],
                'dse_vendor_name' => 'FreeDSx',
                'dse_vendor_version' => null,
                'sasl_mechanisms' => [],
            ],
            $this->subject->getOptions()->toArray(),
        );
    }

    public function test_it_does_not_throw_for_sasl_mechanisms_without_a_sasl_backend(): void
    {
        $this->mockServerRunner->method('run');

        $this->options->setSaslMechanisms(ServerOptions::SASL_PLAIN);

        $this->subject->run();

        $this->expectNotToPerformAssertions();
    }

    public function test_it_should_use_the_password_authenticator_specified(): void
    {
        $authenticator = $this->createMock(PasswordAuthenticatableInterface::class);

        $this->subject->usePasswordAuthenticator($authenticator);

        self::assertSame(
            $authenticator,
            $this->subject->getOptions()->getPasswordAuthenticator()
        );
    }

    public function test_it_should_use_the_write_handler_specified(): void
    {
        $handler = $this->createMock(WriteHandlerInterface::class);

        $this->subject->useWriteHandler($handler);

        self::assertContains(
            $handler,
            $this->subject->getOptions()->getWriteHandlers()
        );
    }

    public function test_it_should_use_the_filter_evaluator_specified(): void
    {
        $evaluator = $this->createMock(FilterEvaluatorInterface::class);

        $this->subject->useFilterEvaluator($evaluator);

        self::assertSame(
            $evaluator,
            $this->subject->getOptions()->getFilterEvaluator()
        );
    }

    public function test_it_should_enable_swoole_runner(): void
    {
        $this->subject->useSwooleRunner();

        self::assertTrue($this->subject->getOptions()->getUseSwooleRunner());
    }

    public function test_it_should_make_a_proxy_server(): void
    {
        $proxyOptions = LdapServer::makeProxy('localhost')->getOptions();

        self::assertInstanceOf(
            ProxyHandler::class,
            $proxyOptions->getBackend()
        );

        self::assertNull($proxyOptions->getRootDseHandler());
    }
}
