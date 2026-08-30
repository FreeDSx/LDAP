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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;

/**
 * Writes the bookkeeping a command carries alongside the caller's own changes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait AppliesSystemChanges
{
    /**
     * Server-stamped values land on the entry beside the operational attributes, exempt from the user rules.
     *
     * @param list<Change> $changes
     */
    private function applySystemChanges(
        Entry $entry,
        array $changes,
    ): void {
        foreach ($changes as $change) {
            if ($change->getType() === Change::TYPE_REPLACE) {
                $entry->set($change->getAttribute());

                continue;
            }

            $entry->reset($change->getAttribute());
        }
    }
}
