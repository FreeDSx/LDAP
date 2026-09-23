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

namespace Tests\Support\FreeDSx\Ldap\Journal;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use PHPUnit\Framework\TestCase;
use Throwable;

/**
 * Test that a change journal allocates a gap-free, collision-free seq run under concurrent writers.
 */
abstract class JournalConcurrencyTestCase extends TestCase
{
    protected const WORKERS = 8;

    protected const WRITES_PER_WORKER = 25;

    protected function setUp(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('The journal concurrency proof requires the pcntl extension.');
        }

        $this->prepareJournalStore();
    }

    public function test_concurrent_forked_writers_allocate_a_gap_free_collision_free_seq_run(): void
    {
        $pids = [];
        for ($worker = 0; $worker < self::WORKERS; $worker++) {
            $pid = pcntl_fork();
            self::assertNotSame(
                -1,
                $pid,
                'pcntl_fork failed',
            );

            if ($pid === 0) {
                exit($this->runWorker());
            }

            $pids[] = $pid;
        }

        $failed = 0;
        foreach ($pids as $pid) {
            $status = 0;
            pcntl_waitpid($pid, $status);

            if (!self::exitedCleanly($status)) {
                $failed++;
            }
        }

        self::assertSame(
            0,
            $failed,
            'every forked writer committed its changes without error',
        );
        self::assertSame(
            range(1, self::WORKERS * self::WRITES_PER_WORKER),
            $this->readSeqs(),
        );
    }

    /**
     * Create the shared underlying store (schema, files) once before forking.
     */
    abstract protected function prepareJournalStore(): void;

    /**
     * A journal on its own connection/instance, sharing the prepared store across forks.
     */
    abstract protected function makeJournal(): ChangeJournalInterface;

    private static function exitedCleanly(mixed $status): bool
    {
        return is_int($status)
            && pcntl_wifexited($status)
            && pcntl_wexitstatus($status) === 0;
    }

    /**
     * Runs in a forked child on its own journal instance; returns the process exit code.
     */
    private function runWorker(): int
    {
        try {
            $journal = $this->makeJournal();
            for ($i = 0; $i < self::WRITES_PER_WORKER; $i++) {
                $journal->append(new PendingChange(
                    changeType: ChangeType::Add,
                    dn: new Dn(sprintf('cn=%d-%d,dc=example,dc=com', getmypid(), $i)),
                    entryUuid: '11111111-1111-4111-8111-111111111111',
                    authzId: AuthzId::anonymous(),
                ));
            }

            return 0;
        } catch (Throwable) {
            return 1;
        }
    }

    /**
     * @return list<int>
     */
    private function readSeqs(): array
    {
        $seqs = array_map(
            static fn(ChangeRecord $record): int => $record->seq,
            iterator_to_array($this->makeJournal()->read()),
        );
        // sort() reindexes to a 0-based list; readers assert against range(1, N).
        sort($seqs);

        return $seqs;
    }
}
