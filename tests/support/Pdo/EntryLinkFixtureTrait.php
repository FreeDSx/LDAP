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

namespace Tests\Support\FreeDSx\Ldap\Pdo;

use PDO;

/**
 * @TODO Remove this once linked attributes fully land.
 */
trait EntryLinkFixtureTrait
{
    /**
     * Writes a member link straight into the table. The write path does not write values into it yet.
     */
    private function linkTogether(
        PDO $pdo,
        string $ownerLcDn,
        string $targetLcDn,
    ): void {
        $pdo->prepare(
            'INSERT INTO entry_attribute_links (owner_entry_id, attr_name_lower, target_entry_id, target_uid)
             SELECT o.entry_id, ?, t.entry_id, \'\'
             FROM entries o, entries t
             WHERE o.lc_dn = ? AND t.lc_dn = ?',
        )->execute([
            'member',
            $ownerLcDn,
            $targetLcDn,
        ]);
    }
}
