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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;

/**
 * Recognizes alias entries (RFC 4512: an entry whose objectClass includes "alias").
 */
final class AliasDetector
{
    private function __construct() {}

    public static function isAlias(Entry $entry): bool
    {
        return $entry
            ->get(AttributeTypeOid::NAME_OBJECT_CLASS)
            ?->has(
                ObjectClassOid::NAME_ALIAS,
                caseSensitive: false,
            ) === true;
    }
}
