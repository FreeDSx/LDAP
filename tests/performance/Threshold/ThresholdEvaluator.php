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

use Tests\Performance\FreeDSx\Ldap\Stats\StatsSnapshot;

/**
 * Compares a StatsSnapshot against a ThresholdSet and reports pass/fail per gate.
 */
final class ThresholdEvaluator
{
    public function evaluate(
        StatsSnapshot $snapshot,
        ThresholdSet $thresholds,
    ): ThresholdResult {
        $gates = [];

        if ($thresholds->maxErrors !== null) {
            $gates[] = $this->evaluateMaxErrors(
                $snapshot,
                $thresholds->maxErrors,
            );
        }

        if ($thresholds->maxErrorRate !== null) {
            $gates[] = $this->evaluateMaxErrorRate(
                $snapshot,
                $thresholds->maxErrorRate,
            );
        }

        if ($thresholds->minThroughput !== null) {
            $gates[] = $this->evaluateMinThroughput(
                $snapshot,
                $thresholds->minThroughput,
            );
        }

        if ($thresholds->maxP99Ms !== null) {
            $gates[] = $this->evaluateMaxP99(
                $snapshot,
                $thresholds->maxP99Ms,
            );
        }

        $passed = true;
        foreach ($gates as $gate) {
            if ($gate['passed']) {
                continue;
            }

            $passed = false;
            break;
        }

        return new ThresholdResult($passed, $gates);
    }

    /**
     * @return array{gate: string, passed: bool, expected: string, actual: string}
     */
    private function evaluateMaxErrors(
        StatsSnapshot $snapshot,
        int $maxErrors,
    ): array {
        $errors = $snapshot->totalErrors();

        return [
            'gate' => 'max-errors',
            'passed' => $errors <= $maxErrors,
            'expected' => sprintf('<= %d', $maxErrors),
            'actual' => (string) $errors,
        ];
    }

    /**
     * @return array{gate: string, passed: bool, expected: string, actual: string}
     */
    private function evaluateMaxErrorRate(
        StatsSnapshot $snapshot,
        float $maxRate,
    ): array {
        $attempts = $snapshot->totalSuccess() + $snapshot->totalErrors();
        $rate = $attempts > 0
            ? $snapshot->totalErrors() / $attempts
            : 0.0;

        return [
            'gate' => 'max-error-rate',
            'passed' => $rate <= $maxRate,
            'expected' => sprintf('<= %.6f', $maxRate),
            'actual' => sprintf('%.6f', $rate),
        ];
    }

    /**
     * @return array{gate: string, passed: bool, expected: string, actual: string}
     */
    private function evaluateMinThroughput(
        StatsSnapshot $snapshot,
        float $minOps,
    ): array {
        $tput = $snapshot->overallThroughput();

        return [
            'gate' => 'min-throughput',
            'passed' => $tput >= $minOps,
            'expected' => sprintf('>= %.2f ops/s', $minOps),
            'actual' => sprintf('%.2f ops/s', $tput),
        ];
    }

    /**
     * @return array{gate: string, passed: bool, expected: string, actual: string}
     */
    private function evaluateMaxP99(
        StatsSnapshot $snapshot,
        float $maxMs,
    ): array {
        $worstOp = null;
        $worstP99Ns = 0;

        foreach ($snapshot->operations() as $op) {
            $p99 = $snapshot->latencyStats($op)['p99'];

            if ($p99 <= $worstP99Ns) {
                continue;
            }

            $worstP99Ns = $p99;
            $worstOp = $op;
        }

        $worstP99Ms = $worstP99Ns / 1_000_000;

        return [
            'gate' => 'max-p99-ms',
            'passed' => $worstP99Ms <= $maxMs,
            'expected' => sprintf('<= %.2f ms', $maxMs),
            'actual' => $worstOp !== null
                ? sprintf('%.2f ms (%s)', $worstP99Ms, $worstOp)
                : 'no data',
        ];
    }
}
