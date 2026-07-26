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

namespace Tests\Unit\FreeDSx\Ldap\Server\Utility;

use FreeDSx\Ldap\Server\Utility\CpuCount;
use PHPUnit\Framework\TestCase;

final class CpuCountTest extends TestCase
{
    /**
     * @var list<string>
     */
    private array $files = [];

    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            @unlink($file);
        }

        $this->files = [];
    }

    public function test_it_counts_a_contiguous_cpu_range(): void
    {
        self::assertSame(
            4,
            $this->subjectFor("Name:\tphp\nCpus_allowed_list:\t0-3\n")->available(),
        );
    }

    public function test_it_counts_a_list_of_ranges_and_single_cpus(): void
    {
        self::assertSame(
            5,
            $this->subjectFor("Cpus_allowed_list:\t0-1,4,10-11\n")->available(),
        );
    }

    public function test_it_counts_a_single_cpu(): void
    {
        self::assertSame(
            1,
            $this->subjectFor("Cpus_allowed_list:\t2\n")->available(),
        );
    }

    public function test_a_bandwidth_quota_lowers_the_count_below_the_affinity_mask(): void
    {
        self::assertSame(
            2,
            $this->subjectFor(
                "Cpus_allowed_list:\t0-7\n",
                '200000 100000',
            )->available(),
        );
    }

    public function test_the_affinity_mask_lowers_the_count_below_the_bandwidth_quota(): void
    {
        self::assertSame(
            2,
            $this->subjectFor(
                "Cpus_allowed_list:\t0-1\n",
                '800000 100000',
            )->available(),
        );
    }

    public function test_an_unlimited_quota_leaves_the_affinity_mask_alone(): void
    {
        self::assertSame(
            8,
            $this->subjectFor(
                "Cpus_allowed_list:\t0-7\n",
                'max 100000',
            )->available(),
        );
    }

    public function test_a_fractional_quota_rounds_down_rather_than_over_subscribing(): void
    {
        self::assertSame(
            1,
            $this->subjectFor(
                "Cpus_allowed_list:\t0-7\n",
                '150000 100000',
            )->available(),
        );
    }

    public function test_a_quota_below_one_cpu_still_yields_a_worker(): void
    {
        self::assertSame(
            1,
            $this->subjectFor(
                "Cpus_allowed_list:\t0-7\n",
                '50000 100000',
            )->available(),
        );
    }

    public function test_it_falls_back_to_the_machine_total_when_nothing_is_readable(): void
    {
        $subject = new CpuCount(
            '/nonexistent/status',
            '/nonexistent/cpu.max',
        );

        self::assertGreaterThanOrEqual(
            1,
            $subject->available(),
        );
    }

    private function subjectFor(
        string $status,
        ?string $quota = null,
    ): CpuCount {
        return new CpuCount(
            $this->fileWith($status),
            $quota === null
                ? '/nonexistent/cpu.max'
                : $this->fileWith($quota),
        );
    }

    private function fileWith(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'freedsx_cpu_');

        if ($path === false) {
            self::fail('Could not create a temporary file.');
        }

        file_put_contents($path, $contents);
        $this->files[] = $path;

        return $path;
    }
}
