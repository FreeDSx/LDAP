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

use function function_exists;
use function is_numeric;
use function posix_getrlimit;

/**
 * The open-file soft limit of the process, checked against the connection limit.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class OpenFileLimit
{
    /**
     * Descriptors a process needs besides its clients, such as its listener and storage files.
     */
    private const SPARE_DESCRIPTORS = 64;

    /**
     * @param int|null $softLimit the number of open files, or null when it is unlimited or unknown.
     */
    public function __construct(private ?int $softLimit) {}

    public static function ofThisProcess(): self
    {
        if (!function_exists('posix_getrlimit')) {
            return new self(null);
        }
        $limit = posix_getrlimit()['soft openfiles'] ?? null;

        return new self(is_numeric($limit) ? (int) $limit : null);
    }

    /**
     * Whether the clients' descriptors run out before the connection limit is reached, where 0 means no limit.
     */
    public function isReachedBefore(
        int $maxConnections,
        int $descriptorsPerClient,
    ): bool {
        if ($this->softLimit === null) {
            return false;
        }

        return $maxConnections <= 0
            || $maxConnections * $descriptorsPerClient + self::SPARE_DESCRIPTORS > $this->softLimit;
    }

    public function getSoftLimit(): ?int
    {
        return $this->softLimit;
    }
}
