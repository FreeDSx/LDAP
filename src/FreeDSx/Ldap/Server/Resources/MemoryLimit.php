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

namespace FreeDSx\Ldap\Server\Resources;

use function ini_get;
use function ini_parse_quantity;

/**
 * The memory limit of the process, checked against the connection limit and the held request size.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class MemoryLimit
{
    /**
     * An idle connection's memory plus what it may always buffer, the floor and one read past it, in bytes.
     */
    private const BYTES_PER_CONNECTION = 45_056;

    /**
     * @param int|null $bytes the limit in bytes, or null when the process has none.
     */
    public function __construct(private ?int $bytes) {}

    public static function ofThisProcess(): self
    {
        $limit = ini_get('memory_limit');
        $bytes = $limit === false || $limit === ''
            ? -1
            : ini_parse_quantity($limit);

        return new self($bytes > 0 ? $bytes : null);
    }

    /**
     * Whether the connections and the requests held at once can need more than the limit, where 0 means no limit.
     */
    public function isReachedBefore(
        int $maxConnections,
        int $maxHeldRequestSize,
    ): bool {
        if ($this->bytes === null) {
            return false;
        }

        return $maxConnections <= 0
            || $maxHeldRequestSize <= 0
            || $maxConnections * self::BYTES_PER_CONNECTION + $maxHeldRequestSize > $this->bytes;
    }

    /**
     * The limit in bytes, or null when the process has none.
     */
    public function getBytes(): ?int
    {
        return $this->bytes;
    }
}
