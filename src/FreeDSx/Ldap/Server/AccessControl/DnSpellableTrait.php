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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;

/**
 * Respells the one DN a matcher names, keeping the same matcher when that DN already uses primary names.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait DnSpellableTrait
{
    public function spelledBy(AttributeTypeSpelling $spelling): static
    {
        $dn = $this->spellableDn();
        $spelled = $spelling->dn($dn);

        return $spelled === $dn
            ? $this
            : $this->withSpellableDn($spelled);
    }

    /**
     * The DN the matcher names.
     */
    abstract private function spellableDn(): Dn;

    /**
     * A copy of the matcher naming the given DN in place of its own.
     */
    abstract private function withSpellableDn(Dn $dn): static;
}
