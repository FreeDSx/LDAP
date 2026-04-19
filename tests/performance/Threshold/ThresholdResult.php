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
 * Outcome of evaluating a StatsSnapshot against a ThresholdSet.
 */
final class ThresholdResult
{
    /**
     * @param list<array{gate: string, passed: bool, expected: string, actual: string}> $gates
     */
    public function __construct(
        public readonly bool $passed,
        public readonly array $gates,
    ) {
    }

    /**
     * @return list<array{gate: string, expected: string, actual: string}>
     */
    public function failedGates(): array
    {
        $failed = [];

        foreach ($this->gates as $gate) {
            if ($gate['passed']) {
                continue;
            }

            $failed[] = [
                'gate' => $gate['gate'],
                'expected' => $gate['expected'],
                'actual' => $gate['actual'],
            ];
        }

        return $failed;
    }
}
