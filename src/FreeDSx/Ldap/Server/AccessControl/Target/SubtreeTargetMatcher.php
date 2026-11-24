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

namespace FreeDSx\Ldap\Server\AccessControl\Target;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\AccessControl\DnSpellableInterface;
use FreeDSx\Ldap\Server\AccessControl\DnSpellableTrait;

/**
 * Matches any target DN within a given subtree (case-insensitive).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SubtreeTargetMatcher implements TargetMatcherInterface, DnSpellableInterface
{
    use DnSpellableTrait;

    private readonly Dn $subtreeDn;

    public function __construct(string $dn)
    {
        $this->subtreeDn = new Dn($dn);
    }

    public function matches(Dn $dn): bool
    {
        return $dn->isDescendantOf($this->subtreeDn);
    }

    private function spellableDn(): Dn
    {
        return $this->subtreeDn;
    }

    private function withSpellableDn(Dn $dn): static
    {
        return new self($dn->toString());
    }
}
