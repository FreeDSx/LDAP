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

namespace Tests\Performance\FreeDSx\Ldap\Threshold;

/**
 * CI gating thresholds for a load-test run. Null members mean "no gate."
 */
final class ThresholdSet
{
    public function __construct(
        public readonly ?float $maxErrorRate = null,
        public readonly ?int $maxErrors = null,
        public readonly ?float $minThroughput = null,
        public readonly ?float $maxP99Ms = null,
    ) {
    }

    public function isEmpty(): bool
    {
        return $this->maxErrorRate === null
            && $this->maxErrors === null
            && $this->minThroughput === null
            && $this->maxP99Ms === null;
    }

    /**
     * Returns a new set where any non-null field on $overrides replaces this set's value.
     */
    public function withOverrides(self $overrides): self
    {
        return new self(
            maxErrorRate: $overrides->maxErrorRate ?? $this->maxErrorRate,
            maxErrors: $overrides->maxErrors ?? $this->maxErrors,
            minThroughput: $overrides->minThroughput ?? $this->minThroughput,
            maxP99Ms: $overrides->maxP99Ms ?? $this->maxP99Ms,
        );
    }
}
