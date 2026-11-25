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
 * Answers which of some values an entry links.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface HeldLinkLookupInterface
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
}
