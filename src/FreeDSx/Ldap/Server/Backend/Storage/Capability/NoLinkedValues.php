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
 * Stands in for storage that keeps values on the entry itself.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class NoLinkedValues implements LinkedValueLookupInterface
{
    /**
     * Nothing to add, since the entry carries every value it holds.
     */
    public function heldLinkValues(
        Dn $owner,
        string $attribute,
        array $values,
    ): array {
        return [];
    }

    /**
     * Nothing to add, since the entry carries every value it holds.
     */
    public function anyLinkValue(
        Dn $owner,
        string $attribute,
    ): ?string {
        return null;
    }
}
