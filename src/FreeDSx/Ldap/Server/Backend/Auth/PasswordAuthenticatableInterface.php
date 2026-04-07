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
     * Return true if the supplied password is valid for the given bind name.
     *
     * The name is the raw value from the LDAP bind request — it need not be a DN.
     */
    public function verifyPassword(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): bool;

    /**
     * Return the plaintext password for the given username and SASL mechanism,
     * or null if the user does not exist or should not authenticate.
     */
    public function getPassword(
        string $username,
        string $mechanism,
    ): ?string;
}
