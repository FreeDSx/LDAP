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

namespace FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Entry\Dn;

/**
 * The configured manager super-user identity: a DN and its hashed password.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ManagerIdentity
{
    public function __construct(
        private Dn $dn,
        private string $hashedPassword,
    ) {}

    public function dn(): Dn
    {
        return $this->dn;
    }

    public function hashedPassword(): string
    {
        return $this->hashedPassword;
    }

    public function matches(Dn $dn): bool
    {
        return $this->dn->normalizedString() === $dn->normalizedString();
    }
}
