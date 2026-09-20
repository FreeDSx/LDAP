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
 * Answers what an entry links without reading the values it links.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface LinkedValueLookupInterface
{
    /**
     * Which of the named values the entry holds, given back as they were asked for.
     *
     * @param list<string> $values
     *
     * @return list<string>
     */
    public function heldLinkValues(
        Dn $owner,
        string $attribute,
        array $values,
    ): array;

    /**
     * Any one value the entry holds, or null when it holds none.
     */
    public function anyLinkValue(
        Dn $owner,
        string $attribute,
    ): ?string;
}
