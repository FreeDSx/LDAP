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

use InvalidArgumentException;

/**
 * How many clients the driver runs, for how long, and which operations they draw from.
 */
final readonly class RunSettings
{
    use AssertsSettingsTrait;

    public const DEFAULT_MIX = 'bind=5,search-read=50,search-eq=25,search-sub=10,search-list=5,search-sort=3,add=2,modify=2,delete=1';

    public const DEFAULT_CLIENTS = 16;

    public const DEFAULT_DURATION = 10;

    public const DEFAULT_WARMUP = 2;

    /**
     * @param ?int $duration Seconds to sample for, or null when the run ends on its ops instead.
     * @param ?int $ops Operations per client, or null when the run ends on its duration instead.
     * @param int $workerIdOffset Where this driver's worker ids start, keeping drivers that share a server apart.
     * @param bool $jit Whether the PHP processes the run spawns enable the function JIT.
     */
    public function __construct(
        public int $clients = self::DEFAULT_CLIENTS,
        public ?int $duration = self::DEFAULT_DURATION,
        public ?int $ops = null,
        public int $warmup = self::DEFAULT_WARMUP,
        public string $mix = self::DEFAULT_MIX,
        public ?int $rngSeed = null,
        public int $workerIdOffset = 0,
        public bool $jit = true,
    ) {
        self::assertPositive(
            'clients',
            $clients,
        );
        self::assertNonNegative(
            'warmup',
            $warmup,
        );
        self::assertNonNegative(
            'worker-id-offset',
            $workerIdOffset,
        );

        if ($duration === null && $ops === null) {
            throw new InvalidArgumentException('One of --duration or --ops must be set.');
        }
        if ($duration !== null) {
            self::assertPositive(
                'duration',
                $duration,
            );
        }
        if ($ops !== null) {
            self::assertPositive(
                'ops',
                $ops,
            );
        }
    }

    /**
     * The settings for one of several drivers sharing a server, seeded and numbered apart from the others.
     */
    public function forChild(int $index): self
    {
        return new self(
            clients: $this->clients,
            duration: $this->duration,
            ops: $this->ops,
            warmup: $this->warmup,
            mix: $this->mix,
            rngSeed: $this->rngSeed === null
                ? null
                : $this->rngSeed + $index,
            workerIdOffset: $index * $this->clients,
            jit: $this->jit,
        );
    }
}
