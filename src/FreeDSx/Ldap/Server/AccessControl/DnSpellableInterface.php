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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Schema\AttributeTypeSpelling;

/**
 * A matcher naming a DN, which it gives again with the attribute types it names spelled by their primary names.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface DnSpellableInterface
{
    /**
     * This matcher when the types it names already use primary names, otherwise a respelled copy.
     */
    public function spelledBy(AttributeTypeSpelling $spelling): static;
}
