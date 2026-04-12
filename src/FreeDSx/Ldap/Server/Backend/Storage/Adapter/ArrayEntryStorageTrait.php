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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use Generator;

/**
 * Provides scope-filtered list helpers for array-backed EntryStorageInterface implementations.
 *
 * Includes DefaultHasChildrenTrait for the default hasChildren() implementation.
 * Use DefaultHasChildrenTrait directly if you only need the hasChildren() default
 * (e.g. for a database-backed adapter that handles list() natively).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ArrayEntryStorageTrait
{
    use DefaultHasChildrenTrait;

    /**
     * @param array<string, Entry> $entries Entries keyed by normalised DN string
     * @return Generator<Entry>
     */
    private function yieldByScope(
        array $entries,
        Dn $baseDn,
        bool $subtree,
        int $timeLimit = 0,
    ): Generator {
        $deadline = $timeLimit > 0
            ? microtime(true) + $timeLimit
            : null;

        foreach ($entries as $normDn => $entry) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                throw new TimeLimitExceededException();
            }

            $entryDn = new Dn($normDn);

            if ($subtree && $entryDn->isDescendantOf($baseDn)) {
                yield $entry;
            } elseif (!$subtree && $entryDn->isChildOf($baseDn)) {
                yield $entry;
            }
        }
    }
}
