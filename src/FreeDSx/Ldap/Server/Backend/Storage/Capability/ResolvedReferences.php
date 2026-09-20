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
 * Stands in for storage that keeps values as written rather than as references, so nothing is ever left unresolved.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ResolvedReferences implements ReferenceIntegrityInterface
{
    /**
     * Never any, since a value kept as written names whatever it says.
     */
    public function unresolvedReferences(Dn $owner): array
    {
        return [];
    }

    /**
     * Never any, since a value kept as written names whatever it says.
     */
    public function hasUnresolvedReferences(): bool
    {
        return false;
    }
}
