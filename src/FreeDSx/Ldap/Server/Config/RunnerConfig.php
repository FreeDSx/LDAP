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

namespace FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Server\Utility\CpuCount;

/**
 * The process model a server runs under.
 *
 * @api
 */
final class RunnerConfig
{
    /**
     * Accept on one worker per available CPU.
     */
    public const AUTO_DETECT_WORKERS = 0;

    private int $workers;

    private ?int $resolvedWorkers = null;

    public function __construct(
        private RunnerMode $mode = RunnerMode::Pcntl,
        int $workers = 1,
    ) {
        $this->setWorkers($workers);
    }

    /**
     * Coroutine handling, accepting on $workers processes, or on one per available CPU when null.
     */
    public static function forSwoole(?int $workers = null): self
    {
        return new self(
            RunnerMode::Swoole,
            $workers ?? self::AUTO_DETECT_WORKERS,
        );
    }

    /**
     * A forked process per connection, which is Linux only.
     */
    public static function forPcntl(): self
    {
        return new self(RunnerMode::Pcntl);
    }

    public function getMode(): RunnerMode
    {
        return $this->mode;
    }

    public function setMode(RunnerMode $mode): self
    {
        $this->mode = $mode;

        return $this;
    }

    /**
     * Worker processes the Swoole runner accepts on.
     *
     * Value of 0 auto-detects the CPU count.
     */
    public function getWorkers(): int
    {
        return $this->workers;
    }

    /**
     * Only the Swoole runner uses this.
     *
     * More than one worker requires a backend that keeps no state in the process, so in-memory storage is clamped
     * back to a single worker.
     */
    public function setWorkers(int $workers): self
    {
        if ($workers < 0) {
            throw new InvalidArgumentException('The worker count cannot be negative.');
        }
        $this->workers = $workers;
        $this->resolvedWorkers = null;

        return $this;
    }

    /**
     * The configured count with auto-detection applied, worked out once and kept.
     */
    public function resolvedWorkers(): int
    {
        return $this->resolvedWorkers ??= $this->workers > 0
            ? $this->workers
            : (new CpuCount())->available();
    }

    /**
     * Whether connections are all served by one process, so they can observe each other through memory alone.
     *
     * A worker count left to auto-detect counts as multiple, since the resolved count depends on the backend.
     */
    public function isSingleProcess(): bool
    {
        return $this->mode === RunnerMode::Swoole
            && $this->workers === 1;
    }
}
