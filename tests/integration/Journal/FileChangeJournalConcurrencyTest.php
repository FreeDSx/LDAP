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

namespace Tests\Integration\FreeDSx\Ldap\Journal;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\FileLock;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\FileChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use Tests\Support\FreeDSx\Ldap\Journal\JournalConcurrencyTestCase;

final class FileChangeJournalConcurrencyTest extends JournalConcurrencyTestCase
{
    private string $base = '';

    protected function tearDown(): void
    {
        // setUp() may skip (no pcntl) before $base is assigned, so there is nothing to clean.
        if ($this->base === '') {
            return;
        }

        foreach (['', '.journal.jsonl', '.journal.seq', '.lock'] as $suffix) {
            $path = $this->base . $suffix;
            if (is_file($path)) {
                @unlink($path);
            }
        }
    }

    protected function prepareJournalStore(): void
    {
        $base = tempnam(sys_get_temp_dir(), 'file-journal-concurrency-');
        self::assertIsString($base);
        $this->base = $base;
    }

    protected function makeJournal(): ChangeJournalInterface
    {
        return new FileChangeJournal(
            new FileLock($this->base),
            $this->base . '.journal.jsonl',
            $this->base . '.journal.seq',
            new ReplicaId('node'),
        );
    }
}
