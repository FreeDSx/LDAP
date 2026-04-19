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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;

/**
 * Bulk-imports entries into an EntryStorageInterface under a single atomic write.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdapImporter
{
    public function __construct(
        private readonly EntryStorageInterface $storage,
    ) {
    }

    /**
     * Persist all entries in one atomic batch; no-op when the list is empty.
     *
     * @param Entry[] $entries
     * @param bool $ignoreValidation when true, skips basic validation. only do this if you know what you're doing.
     * @throws InvalidArgumentException when a non-top-level entry's parent is not present in storage yet
     */
    public function importEntries(
        array $entries,
        bool $ignoreValidation = false,
    ): void {
        if ($entries === []) {
            return;
        }

        if (!$ignoreValidation) {
            $entries = $this->sortByDepth($entries);
        }

        $this->storage->atomic(function (EntryStorageInterface $storage) use ($entries, $ignoreValidation): void {
            foreach ($entries as $entry) {
                if (!$ignoreValidation) {
                    $this->assertParentExists($storage, $entry->getDn());
                }

                $storage->store($entry);
            }
        });
    }

    /**
     * @param Entry[] $entries
     * @return Entry[]
     */
    private function sortByDepth(array $entries): array
    {
        usort(
            $entries,
            static fn (Entry $a, Entry $b): int => $a->getDn()->count() <=> $b->getDn()->count(),
        );

        return $entries;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function assertParentExists(
        EntryStorageInterface $storage,
        Dn $dn,
    ): void {
        $parent = $dn->normalize()->getParent();

        if ($parent === null || $parent->getParent() === null) {
            return;
        }

        if ($storage->exists($parent)) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            'Parent entry "%s" does not exist for "%s".',
            $parent->toString(),
            $dn->toString(),
        ));
    }
}
