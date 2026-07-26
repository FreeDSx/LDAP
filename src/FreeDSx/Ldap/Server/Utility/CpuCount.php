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

use function array_filter;
use function count;
use function explode;
use function file_get_contents;
use function function_exists;
use function is_file;
use function is_readable;
use function max;
use function min;
use function preg_match;
use function swoole_cpu_num;
use function trim;

/**
 * The CPUs this process may actually run on (impacted by container limits, etc).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class CpuCount
{
    /**
     * The CPUs the process is pinned to.
     */
    private const AFFINITY_PATH = '/proc/self/status';

    /**
     * The cgroup v2 bandwidth limit.
     */
    private const QUOTA_PATH = '/sys/fs/cgroup/cpu.max';

    public function __construct(
        private string $affinityPath = self::AFFINITY_PATH,
        private string $quotaPath = self::QUOTA_PATH,
    ) {}

    /**
     * The usable CPU count.
     *
     * Falls back to the machine total where limits cannot be read.
     */
    public function available(): int
    {
        $limits = [
            $this->fromAffinity(),
            $this->fromQuota(),
        ];
        $limits = array_filter(
            $limits,
            static fn(?int $limit): bool => $limit !== null,
        );

        if ($limits === []) {
            return max(
                1,
                $this->machineTotal(),
            );
        }

        return max(
            1,
            (int) min($limits),
        );
    }

    /**
     * The machine total. This counts every CPU regardless of what this process may use.
     */
    private function machineTotal(): int
    {
        return function_exists('swoole_cpu_num')
            ? swoole_cpu_num()
            : 1;
    }

    /**
     * Counts the entries of a "0-3,8,10-11" style CPU list.
     */
    private function fromAffinity(): ?int
    {
        $status = $this->read($this->affinityPath);
        if ($status === null || preg_match('/^Cpus_allowed_list:\s*(\S+)$/m', $status, $matches) !== 1) {
            return null;
        }
        $count = 0;

        foreach (explode(',', $matches[1]) as $range) {
            $bounds = explode('-', $range);
            $count += count($bounds) === 2
                ? ((int) $bounds[1] - (int) $bounds[0]) + 1
                : 1;
        }

        return $count > 0
            ? $count
            : null;
    }

    /**
     * Turns a bandwidth quota into whole CPUs.
     */
    private function fromQuota(): ?int
    {
        $quota = $this->read($this->quotaPath);

        if ($quota === null) {
            return null;
        }

        $parts = explode(' ', trim($quota));
        if (count($parts) !== 2 || $parts[0] === 'max') {
            return null;
        }

        $period = (int) $parts[1];

        return $period > 0
            ? max(1, (int) ((int) $parts[0] / $period))
            : null;
    }

    private function read(string $path): ?string
    {
        if (!is_file($path) || !is_readable($path)) {
            return null;
        }

        $contents = file_get_contents($path);

        return $contents === false
            ? null
            : $contents;
    }
}
