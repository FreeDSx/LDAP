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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal;

use FreeDSx\Ldap\Exception\InvalidArgumentException;

/**
 * Identity of the replica that authored a change.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReplicaId
{
    private const LOCAL = 'local';

    private string $value;

    /**
     * @param ?string $value The identity, or null for the default single-master one.
     */
    public function __construct(?string $value = null)
    {
        if ($value === '') {
            throw new InvalidArgumentException('A replica id cannot be empty.');
        }

        $this->value = $value ?? self::LOCAL;
    }

    public function __toString(): string
    {
        return $this->value;
    }

    /**
     * The default single-master identity.
     */
    public static function local(): self
    {
        return new self();
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
