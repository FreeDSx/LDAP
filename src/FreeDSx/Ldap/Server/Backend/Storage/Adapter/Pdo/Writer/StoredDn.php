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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer;

use FreeDSx\Ldap\Entry\Dn;

/**
 * The forms of a DN an entry row is keyed and stored by, derived once per write.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class StoredDn
{
    private function __construct(
        public Dn $normalized,
        public string $dn,
        public string $lcDn,
        public string $parentLcDn,
    ) {}

    public static function of(Dn $dn): self
    {
        $normalized = $dn->normalize();

        return new self(
            $normalized,
            $dn->toString(),
            $normalized->toString(),
            $normalized->getParent()?->toString() ?? '',
        );
    }
}
