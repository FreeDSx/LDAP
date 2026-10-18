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

namespace Tests\Performance\FreeDSx\Ldap\Config;

use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use InvalidArgumentException;

/**
 * The server a run targets, and how the driver starts it when it spawns one.
 */
final readonly class ServerSettings
{
    use AssertsSettingsTrait;

    public const DEFAULT_HOST = '127.0.0.1';

    public const DEFAULT_PORT = 10389;

    /**
     * Mirrors the realistic ServerOptions default so load tests run bounded rather than with lookthrough disabled.
     */
    public const DEFAULT_MAX_SEARCH_LOOKTHROUGH = 5000;

    public function __construct(
        public Backend $backend,
        public RunnerMode $runner,
        public ServerMode $mode = ServerMode::Spawn,
        public string $host = self::DEFAULT_HOST,
        public int $port = self::DEFAULT_PORT,
        public int $swooleWorkers = 0,
        public bool $monitor = true,
        public bool $journal = false,
        public int $maxSearchLookthrough = self::DEFAULT_MAX_SEARCH_LOOKTHROUGH,
    ) {
        self::assertPositive(
            'port',
            $port,
        );
        self::assertNonNegative(
            'swoole-workers',
            $swooleWorkers,
        );
        self::assertNonNegative(
            'max-search-lookthrough',
            $maxSearchLookthrough,
        );

        if ($backend === Backend::Memory && $runner === RunnerMode::Pcntl) {
            throw new InvalidArgumentException(
                'InMemoryStorage requires the Swoole runner: pcntl fork children each hold their own copy '
                . 'of the seed entries, so writes never propagate between connections.',
            );
        }
    }
}
