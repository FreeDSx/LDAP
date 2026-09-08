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

namespace Tests\Integration\FreeDSx\Ldap\Runner;

use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use Tests\Integration\FreeDSx\Ldap\Runner\Concern\TlsTestsTrait;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

use function extension_loaded;

/**
 * Behavior that runs against every server runner.
 */
abstract class ServerRunnerTestCase extends ServerTestCase
{
    use TlsTestsTrait;
    use RawClientQueueTrait;

    public static function setUpBeforeClass(): void
    {
        if (!static::isRunnerAvailable()) {
            return;
        }
        parent::setUpBeforeClass();

        static::initSharedServer(
            'ldap-server',
            'tcp',
            static::runnerArgs(),
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();
    }

    public function testAnIdleConnectionReceivesANoticeOfDisconnectionOnShutdown(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--shutdown-timeout=10'],
        );

        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            new SimpleBindRequest(
                'cn=user,dc=foo,dc=bar',
                '12345',
            ),
        ));
        $queue->getMessage(1);

        $this->sendServerSignal(SIGTERM);
        try {
            $queue->getMessage();
            self::fail('The connection ended without a notice of disconnection.');
        } catch (UnsolicitedNotificationException $e) {
            self::assertTrue($e->isNoticeOfDisconnection());
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
        } finally {
            $queue->close();
        }
    }

    /**
     * Appends the runner selection to every server this suite starts, including the per-test ones.
     *
     * @param list<string> $extraArgs
     */
    protected function createServerProcess(
        string $transport,
        array $extraArgs = [],
    ): void {
        parent::createServerProcess(
            $transport,
            [...$extraArgs, ...static::runnerArgs()],
        );
    }

    /**
     * Hook for subclasses to name the runner the server runs under.
     *
     * @return list<string>
     */
    protected static function runnerArgs(): array
    {
        return [];
    }

    /**
     * Whether this runner can run here, which the pcntl one cannot without process control.
     */
    protected static function isRunnerAvailable(): bool
    {
        return extension_loaded('pcntl')
            && extension_loaded('posix');
    }
}
