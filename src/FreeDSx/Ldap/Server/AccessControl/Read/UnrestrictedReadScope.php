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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;

/**
 * Reads everything, for the privileged identity that bypasses access control.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class UnrestrictedReadScope implements ReadScopeInterface
{
    public function isCurrent(): bool
    {
        return true;
    }

    public function isEntryVisible(Entry $entry): bool
    {
        return true;
    }

    public function verdict(string $name): ReadVerdict
    {
        return ReadVerdict::Allow;
    }

    public function isReadableOn(
        string $name,
        Dn $dn,
    ): bool {
        return true;
    }

    public function readable(Entry $entry): Entry
    {
        return $entry;
    }
}
