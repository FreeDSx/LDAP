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

use SensitiveParameter;

/**
 * Implemented by anything that can handle bind authentication.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PasswordAuthenticatableInterface
{
    /**
     * Return true if $password is valid for $name; $name is the raw LDAP bind name and need not be a DN.
     */
    public function verifyPassword(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): bool;

    /**
     * Return the plaintext password for $username (SCRAM/CRAM derive keys from plaintext), or null to reject the bind.
     *
     * RFC 5803 pre-computed StoredKey/ServerKey is not supported.
     */
    public function getPassword(
        string $username,
        string $mechanism,
    ): ?string;
}
