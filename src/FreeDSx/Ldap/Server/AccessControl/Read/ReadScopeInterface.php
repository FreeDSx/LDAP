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
 * The read decisions one identity holds for one request.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ReadScopeInterface
{
    /**
     * Whether the policy these decisions came from still decides.
     */
    public function isCurrent(): bool;

    public function isEntryVisible(Entry $entry): bool;

    /**
     * The read decision for an attribute wherever it is held, or PerEntry when the entry holding it decides.
     */
    public function verdict(string $name): ReadVerdict;

    /**
     * Whether the attribute may be read on the entry at this DN.
     */
    public function isReadableOn(
        string $name,
        Dn $dn,
    ): bool;

    /**
     * The entry without the attributes that may not be read, itself when nothing was removed.
     */
    public function readable(Entry $entry): Entry;
}
