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
    ): Generator {
        $normBase = $baseDn->toString();

        foreach ($entries as $normDn => $entry) {
            if ($normBase === '' && $subtree) {
                yield $entry;
            } elseif ($subtree) {
                if ($normDn === $normBase || str_ends_with($normDn, ',' . $normBase)) {
                    yield $entry;
                }
            } else {
                if ((new Dn($normDn))->isChildOf($baseDn)) {
                    yield $entry;
                }
            }
        }
    }
}
