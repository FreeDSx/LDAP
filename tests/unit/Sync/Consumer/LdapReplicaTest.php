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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Consumer;

use Closure;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Server\Config\Replication\ConsumerConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Process\Signals\ShutdownSignalsInterface;
use FreeDSx\Ldap\Sync\Consumer\ChangeApplierInterface;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\InMemoryReplicationCheckpoint;
use FreeDSx\Ldap\Sync\Consumer\LdapReplica;
use FreeDSx\Ldap\Sync\Consumer\PrimaryConnectionFactory;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;
use FreeDSx\Ldap\Sync\SyncRepl;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class LdapReplicaTest extends TestCase
{
    private ChangeApplierInterface&MockObject $applier;

    private InMemoryReplicationCheckpoint $checkpoint;

    private SleeperInterface&MockObject $sleeper;

    private ShutdownSignalsInterface&MockObject $signals;

    private SyncRepl&MockObject $syncRepl;

    private LdapReplica $subject;

    private Closure $shutdown;

    private Closure $refreshDoneHandler;

    private Closure $cookieHandler;

    private Closure $idSetHandler;

    private ?string $usedCookie = null;

    protected function setUp(): void
    {
        $noop = static function (): void {};
        $this->shutdown = $noop;
        $this->refreshDoneHandler = $noop;
        $this->cookieHandler = $noop;
        $this->idSetHandler = $noop;

        $this->applier = $this->createMock(ChangeApplierInterface::class);
        $this->checkpoint = new InMemoryReplicationCheckpoint();
        $this->sleeper = $this->createMock(SleeperInterface::class);
        $this->signals = $this->createMock(ShutdownSignalsInterface::class);
        $this->signals->method('onShutdown')
            ->willReturnCallback(function (callable $handler): void {
                $this->shutdown = Closure::fromCallable($handler);
            });

        $this->syncRepl = $this->createMock(SyncRepl::class);
        $this->syncRepl->method('useCookie')
            ->willReturnCallback(function (?string $cookie): SyncRepl {
                $this->usedCookie = $cookie;

                return $this->syncRepl;
            });
        $this->syncRepl->method('useCookieHandler')
            ->willReturnCallback(function (Closure $handler): SyncRepl {
                $this->cookieHandler = $handler;

                return $this->syncRepl;
            });
        $this->syncRepl->method('useIdSetHandler')
            ->willReturnCallback(function (Closure $handler): SyncRepl {
                $this->idSetHandler = $handler;

                return $this->syncRepl;
            });
        $this->syncRepl->method('useRefreshDoneHandler')
            ->willReturnCallback(function (Closure $handler): SyncRepl {
                $this->refreshDoneHandler = $handler;

                return $this->syncRepl;
            });

        $connectionFactory = $this->createMock(PrimaryConnectionFactory::class);
        $connectionFactory->method('connectSyncRepl')
            ->willReturn($this->syncRepl);

        $this->subject = new LdapReplica(
            connectionFactory: $connectionFactory,
            applier: $this->applier,
            checkpoint: $this->checkpoint,
            sleeper: $this->sleeper,
            signals: $this->signals,
        );
    }

    public function test_a_present_phase_refresh_applies_reconciles_and_checkpoints(): void
    {
        $entry = $this->createMock(SyncEntryResult::class);
        $session = new Session(
            Session::MODE_LISTEN,
            'from-primary',
        );

        $this->syncRepl->method('listen')
            ->willReturnCallback(function (Closure $entryHandler) use ($entry, $session): void {
                $entryHandler($entry, $session);
                ($this->refreshDoneHandler)($session);
                ($this->cookieHandler)('cookie-after');
                ($this->shutdown)();
            });

        $this->applier->expects(self::once())
            ->method('beginRefresh');
        $this->applier->expects(self::once())
            ->method('apply')
            ->with(
                $entry,
                $session,
            );
        $this->applier->expects(self::once())
            ->method('reconcile');

        $this->subject->run();

        self::assertSame(
            'cookie-after',
            $this->checkpoint->read(),
        );
    }

    public function test_a_received_id_set_is_routed_to_the_applier(): void
    {
        $idSet = $this->createMock(SyncIdSetResult::class);
        $session = new Session(
            Session::MODE_LISTEN,
            'from-primary',
        );

        $this->syncRepl->method('listen')
            ->willReturnCallback(function () use ($idSet, $session): void {
                ($this->idSetHandler)($idSet, $session);
                ($this->shutdown)();
            });

        $this->applier->expects(self::once())
            ->method('applyIdSet')
            ->with(
                $idSet,
                $session,
            )
            ->willReturn([]);

        $this->subject->run();
    }

    public function test_an_incremental_refresh_applies_without_reconciling(): void
    {
        $entry = $this->createMock(SyncEntryResult::class);
        $session = (new Session(
            Session::MODE_LISTEN,
            'from-primary',
        ))->markRefreshComplete(true);

        $this->syncRepl->method('listen')
            ->willReturnCallback(function (Closure $entryHandler) use ($entry, $session): void {
                $entryHandler($entry, $session);
                ($this->refreshDoneHandler)($session);
                ($this->shutdown)();
            });

        $this->applier->expects(self::once())
            ->method('apply');
        $this->applier->expects(self::never())
            ->method('reconcile');

        $this->subject->run();
    }

    public function test_it_resumes_from_the_stored_checkpoint_cookie(): void
    {
        $this->checkpoint->write('resume-me');
        $this->syncRepl->method('listen')
            ->willReturnCallback(function (): void {
                ($this->shutdown)();
            });

        $this->subject->run();

        self::assertSame(
            'resume-me',
            $this->usedCookie,
        );
    }

    public function test_it_backs_off_before_reconnecting_after_a_failure(): void
    {
        $this->syncRepl->method('listen')
            ->willReturnCallback(function (): void {
                throw new RuntimeException('connection lost');
            });
        $this->sleeper->expects(self::once())
            ->method('sleep')
            ->with(1.0)
            ->willReturnCallback(function (): void {
                ($this->shutdown)();
            });

        $this->subject->run();
    }

    public function test_for_pcntl_builds_a_replica(): void
    {
        if (!extension_loaded('pcntl')) {
            $this->markTestSkipped('The pcntl extension is required for this test.');
        }

        $this->expectNotToPerformAssertions();

        LdapReplica::forPcntl(
            new ConsumerConfig(new ClientOptions()),
            new InMemoryStorage(),
        );
    }

    public function test_for_swoole_builds_a_replica(): void
    {
        if (!extension_loaded('swoole')) {
            $this->markTestSkipped('The swoole extension is required for this test.');
        }

        $this->expectNotToPerformAssertions();

        LdapReplica::forSwoole(
            new ConsumerConfig(new ClientOptions()),
            new InMemoryStorage(),
        );
    }
}
