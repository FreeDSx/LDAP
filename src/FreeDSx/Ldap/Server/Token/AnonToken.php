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
 * Represents a token for an anonymous bind.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class AnonToken implements TokenInterface
{
    private ?string $username;

    private int $version;

    public function __construct(
        ?string $username = null,
        int $version = 3
    ) {
        $this->username = $username;
        $this->version = $version;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function getPassword(): ?string
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return $this->version;
    }
}
