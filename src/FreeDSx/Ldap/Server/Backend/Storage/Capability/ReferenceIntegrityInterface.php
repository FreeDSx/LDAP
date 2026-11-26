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
use FreeDSx\Ldap\Server\Backend\Storage\Link\UnresolvedReference;

/**
 * What a store has written but could not resolve.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ReferenceIntegrityInterface
{
    /**
     * The attribute names where the entry named something that is not stored.
     *
     * @return list<string>
     */
    public function unresolvedReferences(Dn $owner): array;

    /**
     * The first reference left unresolved, by the order its entry was stored, or null when there is none.
     */
    public function firstUnresolvedReference(): ?UnresolvedReference;
}
