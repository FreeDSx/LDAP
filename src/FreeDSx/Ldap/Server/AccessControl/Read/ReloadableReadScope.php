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

namespace FreeDSx\Ldap\Server\AccessControl\Read;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\AccessControl\ReloadableAccessControl;

/**
 * The decisions of the policy installed when the request began, which stop being current once a reload replaces it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReloadableReadScope implements ReadScopeInterface
{
    public function __construct(
        private ReloadableAccessControl $owner,
        private int $generation,
        private ReadScopeInterface $inner,
    ) {}

    public function isCurrent(): bool
    {
        return $this->owner->generation() === $this->generation
            && $this->inner->isCurrent();
    }

    public function isEntryVisible(Entry $entry): bool
    {
        return $this->inner->isEntryVisible($entry);
    }

    public function verdict(string $name): ReadVerdict
    {
        return $this->inner->verdict($name);
    }

    public function isReadableOn(
        string $name,
        Dn $dn,
    ): bool {
        return $this->inner->isReadableOn(
            $name,
            $dn,
        );
    }

    public function readable(Entry $entry): Entry
    {
        return $this->inner->readable($entry);
    }
}
