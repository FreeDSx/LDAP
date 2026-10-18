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

namespace FreeDSx\Ldap\Server\AccessControl\Read;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;

use function count;

/**
 * Strips an entry to what a read scope's per-attribute decisions allow.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ReadsEntryAttributesTrait
{
    abstract public function isReadableOn(
        string $name,
        Dn $dn,
    ): bool;

    public function readable(Entry $entry): Entry
    {
        $dn = $entry->getDn();
        $all = $entry->getAttributes();
        $kept = [];

        foreach ($all as $attribute) {
            if ($this->isReadableOn(Attribute::normalizeName($attribute->getName()), $dn)) {
                $kept[] = $attribute;
            }
        }

        if (count($kept) === count($all)) {
            return $entry;
        }

        return Entry::raw(
            $dn,
            $kept,
        );
    }
}
