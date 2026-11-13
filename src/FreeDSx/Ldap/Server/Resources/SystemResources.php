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

namespace FreeDSx\Ldap\Server\Resources;

use function gc_collect_cycles;

/**
 * The resources this process may use.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SystemResources
{
    private ?int $cpuCount = null;

    private readonly OpenFileLimit $openFileLimit;

    private readonly MemoryLimit $memoryLimit;

    public function __construct(
        private readonly CpuCount $cpus = new CpuCount(),
        ?OpenFileLimit $openFileLimit = null,
        ?MemoryLimit $memoryLimit = null,
    ) {
        $this->openFileLimit = $openFileLimit ?? OpenFileLimit::ofThisProcess();
        $this->memoryLimit = $memoryLimit ?? MemoryLimit::ofThisProcess();
    }

    /**
     * The CPUs this process may run on, read the first time it is asked for.
     */
    public function cpuCount(): int
    {
        return $this->cpuCount ??= $this->cpus->available();
    }

    public function openFileLimit(): OpenFileLimit
    {
        return $this->openFileLimit;
    }

    public function memoryLimit(): MemoryLimit
    {
        return $this->memoryLimit;
    }

    /**
     * Frees memory held only by reference cycles, returning how many cycles were collected.
     */
    public function reclaimMemory(): int
    {
        return gc_collect_cycles();
    }
}
