<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\Token;

/**
 * Represents a generic authentication token.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface TokenInterface
{
    public function getUsername(): ?string;

    public function getPassword(): ?string;

    public function getVersion(): int;
}
