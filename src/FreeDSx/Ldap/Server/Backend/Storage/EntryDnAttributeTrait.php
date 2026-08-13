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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;

use function strcasecmp;

/**
 * Recognizes the entryDN description, whose value comes from the entry itself rather than from stored values.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait EntryDnAttributeTrait
{
    /**
     * Whether a description names entryDN, by either its name or its OID.
     */
    private static function isEntryDnAttribute(string $attributeDescription): bool
    {
        $type = Attribute::normalizeName($attributeDescription);

        return strcasecmp($type, AttributeTypeOid::NAME_ENTRY_DN) === 0
            || $type === AttributeTypeOid::OID_ENTRY_DN;
    }
}
