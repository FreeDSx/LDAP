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

namespace Tests\Support\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Utility\Uuid;

use function array_map;
use function array_values;
use function md5;

/**
 * Gives a test fixture the entryUUID storage requires, in place, so a test holding the entry still compares equal to it.
 */
final class EntryFixture
{
    private function __construct() {}

    /**
     * Derived from the DN so storing a DN again is the same entry, while an entry already carrying one keeps it.
     */
    public static function withUuid(Entry $entry): Entry
    {
        if (!$entry->has(AttributeTypeOid::NAME_ENTRY_UUID)) {
            $entry->set(
                AttributeTypeOid::NAME_ENTRY_UUID,
                Uuid::fromBinary(md5(
                    $entry->getDn()->normalizedString(),
                    true,
                )),
            );
        }

        return $entry;
    }

    /**
     * @return list<Entry>
     */
    public static function allWithUuid(Entry ...$entries): array
    {
        return array_values(array_map(
            self::withUuid(...),
            $entries,
        ));
    }

    /**
     * An in-memory store holding the given entries, each given the entryUUID it requires.
     */
    public static function inMemoryStorage(Entry ...$entries): InMemoryStorage
    {
        return new InMemoryStorage(self::allWithUuid(...$entries));
    }
}
