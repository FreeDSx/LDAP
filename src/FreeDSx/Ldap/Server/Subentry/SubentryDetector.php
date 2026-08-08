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

namespace FreeDSx\Ldap\Server\Subentry;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;

use function strcasecmp;

/**
 * Recognizes subentries (RFC 3672: an entry whose objectClass includes "subentry").
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SubentryDetector
{
    private function __construct() {}

    public static function isSubentry(Entry $entry): bool
    {
        $objectClass = $entry->get(AttributeTypeOid::NAME_OBJECT_CLASS);

        if ($objectClass === null) {
            return false;
        }

        foreach ($objectClass->getValues() as $value) {
            if (strcasecmp($value, ObjectClassOid::NAME_SUBENTRY) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the entry is selected by the given visibility.
     */
    public static function isVisibleUnder(
        Entry $entry,
        SubentryVisibility $subentries,
    ): bool {
        return match ($subentries) {
            SubentryVisibility::All => true,
            SubentryVisibility::Hide => !self::isSubentry($entry),
            SubentryVisibility::Only => self::isSubentry($entry),
        };
    }
}
