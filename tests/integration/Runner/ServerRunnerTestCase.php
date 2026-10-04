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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
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

    public function testTheConnectionLimitHoldsAcrossTheWholeServer(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--max-connections=2'],
        );

        $bound = [];
        for ($i = 0; $i < 6; $i++) {
            $client = $this->buildClient('tcp');
            if ($this->bindsUser($client)) {
                $bound[] = $client;
            }
        }

        self::assertCount(
            2,
            $bound,
        );
    }

    public function testAReloadedAccessPolicyReachesASessionAlreadyOpen(): void
    {
        $this->requirePosix();
        $flagFile = $this->makeFlagFile();
        $this->createServerProcess(
            'tcp',
            ['--log', '--reload-flag-file=' . $flagFile],
        );
        $session = $this->buildClient('tcp');
        $session->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $before = $session->read('cn=user,dc=foo,dc=bar');
            file_put_contents(
                $flagFile,
                'deny-sn',
            );
            $this->reloadServer();
            $after = $session->read('cn=user,dc=foo,dc=bar');

            self::assertTrue($before?->has('sn'));
            self::assertFalse($after?->has('sn'));
        } finally {
            @unlink($flagFile);
        }
    }

    public function testAPagedSearchContinuesUnderTheReloadedAccessPolicy(): void
    {
        $this->requirePosix();
        $flagFile = $this->makeFlagFile();
        $this->createServerProcess(
            'tcp',
            ['--log', '--reload-flag-file=' . $flagFile, '--entries=10'],
        );
        $session = $this->buildClient('tcp');
        $session->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
        $paging = $session->paging(
            Operations::search(Filters::startsWith('cn', 'entry-'))->base('dc=foo,dc=bar'),
            5,
        );

        try {
            $before = $paging->getEntries()->toArray();
            file_put_contents(
                $flagFile,
                'deny-sn',
            );
            $this->reloadServer();
            $after = $paging->getEntries()->toArray();

            self::assertSame(
                [5, 5],
                [count($before), count($this->withSn($before))],
            );
            self::assertSame(
                [5, 0],
                [count($after), count($this->withSn($after))],
            );
        } finally {
            @unlink($flagFile);
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

    protected function reloadServer(): void
    {
        $this->sendServerSignal(SIGHUP);
        $this->waitForServerOutput('Server configuration reloaded');
    }

    protected function makeFlagFile(): string
    {
        $flagFile = sys_get_temp_dir() . '/freedsx_runner_reload_' . uniqid('', true);
        file_put_contents(
            $flagFile,
            '',
        );

        return $flagFile;
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

    protected function bindsUser(LdapClient $client): bool
    {
        try {
            $client->sendAndReceive(Operations::bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            ));
        } catch (ConnectionException) {
            return false;
        }

        return true;
    }

    /**
     * @param Entry[] $entries
     * @return Entry[]
     */
    private function withSn(array $entries): array
    {
        return array_filter(
            $entries,
            static fn(Entry $entry): bool => $entry->has('sn'),
        );
    }
}
