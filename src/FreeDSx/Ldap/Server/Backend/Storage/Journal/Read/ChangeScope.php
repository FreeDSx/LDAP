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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Read;

use FreeDSx\Ldap\Entry\Dn;

/**
 * A base DN plus extent that decides whether a change falls within a consumer's view.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ChangeScope
{
    private function __construct(
        private Dn $baseDn,
        private ScopeType $type,
    ) {}

    public static function baseObject(Dn $baseDn): self
    {
        return new self(
            $baseDn,
            ScopeType::BaseObject,
        );
    }

    public static function oneLevel(Dn $baseDn): self
    {
        return new self(
            $baseDn,
            ScopeType::OneLevel,
        );
    }

    public static function wholeSubtree(Dn $baseDn): self
    {
        return new self(
            $baseDn,
            ScopeType::WholeSubtree,
        );
    }

    public function contains(Dn $dn): bool
    {
        return match ($this->type) {
            ScopeType::BaseObject => $dn->normalizedString() === $this->baseDn->normalizedString(),
            ScopeType::OneLevel => $dn->isChildOf($this->baseDn),
            ScopeType::WholeSubtree => $dn->isDescendantOf($this->baseDn),
        };
    }
}
