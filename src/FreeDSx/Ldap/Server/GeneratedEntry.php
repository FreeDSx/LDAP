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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Entry\Dn;

/**
 * The entries this server composes on demand rather than reading from storage.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum GeneratedEntry: string
{
    case RootDse = '';

    case Subschema = 'cn=Subschema';

    case Monitor = 'cn=monitor';

    /**
     * Compared as names rather than as text, so a client spelling the DN differently still resolves to it.
     */
    public static function at(?Dn $dn): ?self
    {
        if ($dn === null) {
            return null;
        }

        foreach (self::cases() as $entry) {
            if ($dn->equals($entry->dn())) {
                return $entry;
            }
        }

        return null;
    }

    public function dn(): Dn
    {
        return new Dn($this->value);
    }

    public function label(): string
    {
        return match ($this) {
            self::RootDse => 'RootDSE',
            self::Subschema => 'subschema entry',
            self::Monitor => self::Monitor->value . ' entry',
        };
    }
}
