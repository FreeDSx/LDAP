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

namespace FreeDSx\Ldap\Server\Token;

/**
 * Represents a username/password token that is bound and authorized.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class BindToken implements TokenInterface
{
    private string $username;

    private string $password;

    private int $version;

    public function __construct(
        string $username,
        string $password,
        int $version = 3
    ) {
        $this->username = $username;
        $this->password = $password;
        $this->version = $version;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return $this->version;
    }
}
