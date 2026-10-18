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

namespace FreeDSx\Ldap\Server\Backend\Storage\Capability;

use FreeDSx\Ldap\Entry\Dn;

/**
 * Counts what an entry links without reading the values it links.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface LinkedValueCountInterface
{
    /**
     * How many values the entry links for the attribute, counted no further than the bound.
     */
    public function linkCount(
        Dn $owner,
        string $attribute,
        int $upTo,
    ): int;
}
