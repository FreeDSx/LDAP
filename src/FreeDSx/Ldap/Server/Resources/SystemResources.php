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

    public function __construct(
        private readonly CpuCount $cpus = new CpuCount(),
        ?OpenFileLimit $openFileLimit = null,
    ) {
        $this->openFileLimit = $openFileLimit ?? OpenFileLimit::ofThisProcess();
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
}
