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

namespace Tests\Performance\FreeDSx\Ldap\LoadTest;

use InvalidArgumentException;

/**
 * Immutable configuration for the load-test driver; built by LoadTestCommand from CLI input.
 */
final class Config
{
    /**
     * @var list<string>
     */
    public const BACKENDS = [
        'memory',
        'json',
        'sqlite',
    ];

    /**
     * @var list<string>
     */
    public const RUNNERS = [
        'pcntl',
        'swoole',
    ];

    /**
     * @var list<string>
     */
    public const SERVER_MODES = [
        'spawn',
        'external',
    ];

    /**
     * @var list<string>
     */
    public const OUTPUTS = [
        'text',
        'json',
    ];

    public const DEFAULT_MIX = 'bind=5,search-read=50,search-eq=25,search-sub=10,search-list=5,add=2,modify=2,delete=1';

    public function __construct(
        public readonly string $backend,
        public readonly string $runner,
        public readonly int $clients = 16,
        public readonly ?int $duration = 10,
        public readonly ?int $ops = null,
        public readonly string $mix = self::DEFAULT_MIX,
        public readonly string $host = '127.0.0.1',
        public readonly int $port = 10389,
        public readonly int $warmup = 2,
        public readonly string $serverMode = 'spawn',
        public readonly ?int $seed = null,
        public readonly string $output = 'text',
        public readonly int $seedEntries = 100,
    ) {
        $this->assertEnum('backend', $backend, self::BACKENDS);
        $this->assertEnum('runner', $runner, self::RUNNERS);
        $this->assertEnum('server', $serverMode, self::SERVER_MODES);
        $this->assertEnum('output', $output, self::OUTPUTS);
        $this->assertPositive('clients', $clients);
        $this->assertPositive('port', $port);
        $this->assertNonNegative('warmup', $warmup);
        $this->assertNonNegative('seed-entries', $seedEntries);

        if ($duration !== null) {
            $this->assertPositive('duration', $duration);
        }
        if ($ops !== null) {
            $this->assertPositive('ops', $ops);
        }
        if ($duration === null && $ops === null) {
            throw new InvalidArgumentException('One of --duration or --ops must be set.');
        }
        if ($backend === 'memory' && $runner === 'pcntl') {
            throw new InvalidArgumentException(
                'InMemoryStorage requires the Swoole runner: pcntl fork children each hold their own copy '
                . 'of the seed entries, so writes never propagate between connections.'
            );
        }
    }

    /**
     * @param list<string> $allowed
     */
    private function assertEnum(string $name, string $value, array $allowed): void
    {
        if (in_array($value, $allowed, true)) {
            return;
        }

        throw new InvalidArgumentException(sprintf(
            'Invalid --%s value "%s". Expected one of: %s.',
            $name,
            $value,
            implode(', ', $allowed)
        ));
    }

    private function assertPositive(string $name, int $value): void
    {
        if ($value > 0) {
            return;
        }

        throw new InvalidArgumentException("--{$name} must be greater than zero, got {$value}.");
    }

    private function assertNonNegative(string $name, int $value): void
    {
        if ($value >= 0) {
            return;
        }

        throw new InvalidArgumentException("--{$name} must be zero or greater, got {$value}.");
    }
}
