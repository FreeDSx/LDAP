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

/**
 * Accumulates per-op latency samples and error counts while recording is enabled.
 *
 * Samples are capped per op via reservoir sampling to bound memory.
 */
final class StatsCollector
{
    public const SAMPLE_CAP = 10_000_000;

    private bool $recording = false;

    /**
     * @var array<string, array<int, int>> op -> sampled nanosecond latencies (size <= SAMPLE_CAP).
     *                                     Not typed as list<int> because reservoir overwrites break the list shape.
     */
    private array $samples = [];

    /**
     * @var array<string, int> op -> total successful ops observed while recording
     */
    private array $counts = [];

    /**
     * @var array<string, int> op -> error count while recording
     */
    private array $errors = [];

    /**
     * @var array<string, array<string, int>> op -> exception class -> count
     */
    private array $errorClasses = [];

    /**
     * @var array<string, int> "fromOp->toOp" -> count (e.g. "modify->add")
     */
    private array $substituted = [];

    public function startRecording(): void
    {
        $this->recording = true;
    }

    public function stopRecording(): void
    {
        $this->recording = false;
    }

    public function isRecording(): bool
    {
        return $this->recording;
    }

    public function recordSuccess(string $op, int $nanos): void
    {
        if (!$this->recording) {
            return;
        }

        $seen = ($this->counts[$op] ?? 0) + 1;
        $this->counts[$op] = $seen;

        if (!isset($this->samples[$op])) {
            $this->samples[$op] = [];
        }

        if ($seen <= self::SAMPLE_CAP) {
            $this->samples[$op][] = $nanos;

            return;
        }

        $slot = mt_rand(0, $seen - 1);
        if ($slot < self::SAMPLE_CAP) {
            $this->samples[$op][$slot] = $nanos;
        }
    }

    public function recordError(string $op, string $exceptionClass): void
    {
        if (!$this->recording) {
            return;
        }

        $this->errors[$op] = ($this->errors[$op] ?? 0) + 1;
        $this->errorClasses[$op][$exceptionClass] = ($this->errorClasses[$op][$exceptionClass] ?? 0) + 1;
    }

    public function recordSubstitution(string $fromOp, string $toOp): void
    {
        if (!$this->recording) {
            return;
        }

        $key = "{$fromOp}->{$toOp}";
        $this->substituted[$key] = ($this->substituted[$key] ?? 0) + 1;
    }

    public function snapshot(float $elapsedSeconds): StatsSnapshot
    {
        return new StatsSnapshot(
            samples: $this->samples,
            counts: $this->counts,
            errors: $this->errors,
            errorClasses: $this->errorClasses,
            substituted: $this->substituted,
            elapsedSeconds: max($elapsedSeconds, 0.000001),
        );
    }
}
