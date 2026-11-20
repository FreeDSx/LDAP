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

namespace Tests\Support\FreeDSx\Ldap\Sync\Convergence;

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;

/**
 * Reads through to storage, running a scheduled write just before a chosen fetch by entryUUID.
 */
final class DriftingEntryReader implements ReadEntryInterface
{
    private ?Closure $write = null;

    private int $fetchesLeft = 0;

    public function __construct(private readonly ReadEntryInterface $reader) {}

    /**
     * Runs the write before the given fetch, counting from one.
     */
    public function beforeFetch(
        int $fetch,
        Closure $write,
    ): void {
        $this->fetchesLeft = $fetch;
        $this->write = $write;
    }

    /**
     * Drops a write whose fetch never came.
     */
    public function disarm(): void
    {
        $this->write = null;
    }

    public function find(
        Dn $dn,
        EntryProjection $projection = new EntryProjection(),
    ): ?Entry {
        return $this->reader->find(
            $dn,
            $projection,
        );
    }

    public function findByUuid(
        string $uuid,
        EntryProjection $projection = new EntryProjection(),
    ): ?Entry {
        $this->drift();

        return $this->reader->findByUuid(
            $uuid,
            $projection,
        );
    }

    public function exists(Dn $dn): bool
    {
        return $this->reader->exists($dn);
    }

    public function hasChildren(Dn $dn): bool
    {
        return $this->reader->hasChildren($dn);
    }

    public function namingContexts(): array
    {
        return $this->reader->namingContexts();
    }

    private function drift(): void
    {
        if ($this->write === null || --$this->fetchesLeft > 0) {
            return;
        }
        $write = $this->write;
        $this->write = null;

        $write();
    }
}
