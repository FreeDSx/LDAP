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

namespace Tests\Support\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Ldif\LdifWriter;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use Random\Engine\Mt19937;
use Random\Randomizer;
use Tests\Support\FreeDSx\Ldap\Sync\Convergence\ConvergenceProvider;
use Tests\Support\FreeDSx\Ldap\Sync\Convergence\ConvergenceReplica;
use Tests\Support\FreeDSx\Ldap\Sync\Convergence\DirectorySnapshot;
use Tests\Support\FreeDSx\Ldap\Sync\Convergence\SyncLoopback;
use Tests\Support\FreeDSx\Ldap\Sync\Convergence\SyncOperations;
use Throwable;

use function array_map;
use function implode;
use function range;
use function sprintf;

/**
 * Drives a provider and a replica through seeded random change windows, restarts and crashes, checking they agree.
 */
trait SyncConvergenceTests
{
    private const WINDOWS = 6;

    private const MAX_CHANGES_PER_WINDOW = 4;

    private const MAX_FETCH_BEFORE_DRIFT = 3;

    private const MAX_MESSAGES_BEFORE_CRASH = 6;

    /**
     * One window in this many holds a write back to land while the sync reads an entry.
     */
    private const DRIFT_ODDS = 4;

    private int $seed;

    private Randomizer $random;

    private ConvergenceProvider $provider;

    private ConvergenceReplica $replica;

    private SyncOperations $operations;

    private SyncLoopback $sync;

    private LdifWriter $ldif;

    /**
     * Whether a sync started now should resume from the checkpoint rather than refresh in full.
     */
    private bool $expectCookie = false;

    /**
     * Whether the current sync was started expecting to resume from the checkpoint.
     */
    private bool $syncExpectsCookie = false;

    /**
     * @var list<string>
     */
    private array $log = [];

    /**
     * @return iterable<string, array{int}>
     */
    public static function seeds(): iterable
    {
        $seeds = range(
            1,
            static::seedCount(),
        );

        foreach ($seeds as $seed) {
            yield 'seed ' . $seed => [$seed];
        }
    }

    #[DataProvider('seeds')]
    public function test_a_replica_converges_with_its_provider(int $seed): void
    {
        $this->start($seed);
        $this->runWindows();
        $this->restartFromCheckpoint();
        $this->restartWithoutCheckpoint();
    }

    /**
     * The storage the provider and the replica each keep their entries in.
     */
    abstract protected function storage(): StorageConfigInterface;

    /**
     * How many seeds a run covers.
     */
    abstract protected static function seedCount(): int;

    /**
     * Member values the storage cannot keep in step, keyed by the lowercased entryUUID they name.
     *
     * @return array<string, true>
     */
    abstract protected function unfollowedMembers(ConvergenceProvider $provider): array;

    private function start(int $seed): void
    {
        $this->seed = $seed;
        $this->random = new Randomizer(new Mt19937($seed));
        $this->ldif = new LdifWriter();
        $this->provider = ConvergenceProvider::on($this->storage());

        foreach (SyncOperations::layout() as $request) {
            $this->write($request);
        }
        $this->replica = ConvergenceReplica::on($this->storage());
        $this->operations = new SyncOperations(
            $this->random,
            $this->provider,
        );
        $this->restart();
        $this->settle();
        $this->expectCookie = true;
    }

    /**
     * Each window's changes reach the replica before the next window, one window cut short by a crash.
     */
    private function runWindows(): void
    {
        $crashWindow = $this->upTo(self::WINDOWS);

        for ($window = 1; $window <= self::WINDOWS; $window++) {
            $this->log[] = "# window {$window}\n";
            $this->writeChanges(drift: true);

            if ($window === $crashWindow) {
                $this->crash();
            }
            $this->settle();
        }
    }

    /**
     * Resumes from the checkpoint after changes made while the replica was down, sometimes crashing during the refresh.
     */
    private function restartFromCheckpoint(): void
    {
        $this->log[] = "# restart from the checkpoint\n";
        $this->writeChanges(drift: false);
        $this->restart();
        $this->maybeCrash();
        $this->settle();
    }

    /**
     * Refreshes in full against what the replica already holds, as a restart that lost its checkpoint does.
     */
    private function restartWithoutCheckpoint(): void
    {
        $this->log[] = "# restart without the checkpoint\n";
        $this->writeChanges(drift: false);
        $this->replica->forgetCheckpoint();
        $this->expectCookie = false;
        $this->restart();
        $this->maybeCrash();
        $this->settle();
    }

    /**
     * Writes a few random changes, sometimes holding one back to land while the sync reads an entry.
     */
    private function writeChanges(bool $drift): void
    {
        $changes = $this->upTo(self::MAX_CHANGES_PER_WINDOW);

        for ($change = 1; $change <= $changes; $change++) {
            foreach ($this->operations->next() as $request) {
                $this->write($request);
            }
        }

        if (!$drift || $this->upTo(self::DRIFT_ODDS) !== 1) {
            return;
        }
        $fetch = $this->upTo(self::MAX_FETCH_BEFORE_DRIFT);
        $request = $this->operations->next()[0];

        $this->log[] = "# before fetch {$fetch}:\n" . $this->ldif->writeOne($request);
        $this->provider->writeBeforeFetch(
            $fetch,
            $request,
        );
    }

    private function maybeCrash(): void
    {
        if ($this->upTo(2) === 1) {
            $this->crash();
        }
    }

    /**
     * Cuts the sync off after a few messages, then starts a fresh consumer from what the checkpoint kept.
     */
    private function crash(): void
    {
        $handled = $this->upTo(self::MAX_MESSAGES_BEFORE_CRASH);
        $pollEnded = $this->drain($handled);

        $this->log[] = $pollEnded
            ? "# restart at the end of a poll\n"
            : "# crash after {$handled} messages\n";
        $this->provider->cancelDrift();
        $this->assertSyncedWithinBounds();
        // A refresh that completed before the cut left a checkpoint to resume from.
        $this->expectCookie = $this->expectCookie || $this->replica->checkpointSeq() !== null;
        $this->restart();
    }

    private function restart(): void
    {
        $this->syncExpectsCookie = $this->expectCookie;
        $this->sync = new SyncLoopback(
            $this->provider->sync(...),
            $this->replica->consumer(),
        );
    }

    /**
     * Two polls, as a write landing during the first one's fetch only reaches the journal after it.
     */
    private function settle(): void
    {
        $this->drain();
        $this->drain();
        $this->provider->cancelDrift();

        $this->assertSyncedWithinBounds();
        self::assertSame(
            $this->provider->latestSeq(),
            $this->replica->checkpointSeq(),
            $this->report("The replica's checkpoint did not reach the provider's last change"),
        );
        $this->assertSameContent();
    }

    /**
     * @return bool whether a poll ended before the limit
     */
    private function drain(?int $limit = null): bool
    {
        try {
            return $this->sync->drain($limit);
        } catch (Throwable $e) {
            self::fail($this->report(sprintf(
                'The sync failed with %s: %s at %s:%d',
                $e::class,
                $e->getMessage(),
                $e->getFile(),
                $e->getLine(),
            )));
        }
    }

    private function assertSyncedWithinBounds(): void
    {
        self::assertSame(
            [],
            $this->sync->leaks(),
            $this->report('A sync named a hidden entry'),
        );
        $failure = $this->syncExpectsCookie
            ? 'The sync did not resume from the checkpoint'
            : 'The sync did not refresh in full';

        self::assertSame(
            !$this->syncExpectsCookie,
            $this->sync->startedWithoutCookie(),
            $this->report($failure),
        );
    }

    private function assertSameContent(): void
    {
        $provider = $this->provider->snapshot();
        $replica = $this->replica->snapshot();

        self::assertSame(
            $provider->dns,
            $replica->dns,
            $this->report("The replica's entries differ from its provider's"),
        );
        self::assertSame(
            $provider->attributes,
            $replica->attributes,
            $this->report("The replica's attributes differ from its provider's"),
        );
        $this->assertSameMembers(
            $provider,
            $replica,
        );
    }

    private function assertSameMembers(
        DirectorySnapshot $provider,
        DirectorySnapshot $replica,
    ): void {
        $unfollowed = $this->unfollowedMembers($this->provider);

        self::assertSame(
            $provider->withoutMembersNaming($unfollowed)->members,
            $replica->withoutMembersNaming($unfollowed)->members,
            $this->report("The replica's group members differ from its provider's"),
        );
    }

    private function write(RequestInterface $request): void
    {
        $applied = $this->provider->write($request);

        $this->log[] = ($applied ? '' : "# refused:\n") . $this->ldif->writeOne($request);
    }

    private function upTo(int $max): int
    {
        return $this->random->getInt(
            1,
            $max,
        );
    }

    private function report(string $failure): string
    {
        $logged = array_map(
            static fn(array $record): string => $record['message'],
            $this->replica->logger->records,
        );

        return sprintf(
            "%s (seed %d).\n%s\n%s",
            $failure,
            $this->seed,
            implode(
                "\n",
                $this->log,
            ),
            implode(
                "\n",
                $logged,
            ),
        );
    }
}
