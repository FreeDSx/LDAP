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

namespace Tests\Support\FreeDSx\Ldap;

use function getenv;
use function sprintf;
use function sys_get_temp_dir;

/**
 * Scopes the ports and files a test server uses to the worker running it, so parallel workers cannot collide.
 *
 * Spawned server processes inherit the environment, so they derive the same values as the test that started them.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class TestWorker
{
    /**
     * The upstream a proxy test puts behind itself.
     */
    public const OFFSET_UPSTREAM = 1;

    /**
     * The provider a replication test reads from.
     */
    public const OFFSET_PROVIDER = 2;

    /**
     * The port a serial run uses, kept as-is so a lone worker listens where it always has.
     */
    private const BASE_PORT = 10389;

    /**
     * Ports reserved per worker, leaving room for the upstream and provider a single test also spawns.
     */
    private const PORT_STRIDE = 10;

    private function __construct() {}

    /**
     * Index of the parallel worker running this process; 0 when the suite runs serially.
     */
    public static function token(): int
    {
        $token = getenv('TEST_TOKEN');

        return $token === false
            ? 0
            : (int) $token;
    }

    public static function port(int $offset = 0): int
    {
        return self::BASE_PORT
            + (self::token() * self::PORT_STRIDE)
            + $offset;
    }

    /**
     * A worker-scoped path under the system temp directory.
     */
    public static function path(string $name): string
    {
        return sprintf(
            '%s/freedsx_%d_%s',
            sys_get_temp_dir(),
            self::token(),
            $name,
        );
    }
}
