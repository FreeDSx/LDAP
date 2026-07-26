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

namespace FreeDSx\Ldap\Server\Utility;

use FreeDSx\Ldap\Exception\InvalidArgumentException;

use function min;
use function random_int;

/**
 * A bounded exponential backoff with jitter, for spacing out retries of a contended operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ExponentialBackoff
{
    /**
     * Resolution of the random draw used to spread a delay across its jitter window.
     */
    private const JITTER_STEPS = 1_000;

    /**
     * @param float $jitter Fraction of the delay to spread it by, from 0.0 (none) to 1.0 (down to zero or double).
     */
    public function __construct(
        private float $base,
        private float $max,
        private float $jitter = 0.5,
    ) {
        if ($this->base <= 0.0) {
            throw new InvalidArgumentException('The backoff base delay must be greater than zero.');
        }

        if ($this->max < $this->base) {
            throw new InvalidArgumentException('The backoff ceiling cannot be less than the base delay.');
        }

        if ($this->jitter < 0.0 || $this->jitter > 1.0) {
            throw new InvalidArgumentException('The backoff jitter must be between 0.0 and 1.0.');
        }
    }

    /**
     * The delay before the given attempt, doubling per attempt up to the ceiling.
     */
    public function delayFor(int $attempt): float
    {
        if ($attempt < 1) {
            throw new InvalidArgumentException('The backoff attempt must be one or greater.');
        }

        $delay = min(
            $this->base * (2 ** ($attempt - 1)),
            $this->max,
        );

        return $this->jittered($delay);
    }

    private function jittered(float $delay): float
    {
        if ($this->jitter === 0.0) {
            return $delay;
        }

        $spread = $delay * $this->jitter;
        $position = random_int(0, self::JITTER_STEPS) / self::JITTER_STEPS;

        return $delay - $spread + ($spread * 2.0 * $position);
    }
}
