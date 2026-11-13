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

namespace Tests\Unit\FreeDSx\Ldap\Server\Resources;

use FreeDSx\Ldap\Server\Resources\CpuCount;
use FreeDSx\Ldap\Server\Resources\OpenFileLimit;
use FreeDSx\Ldap\Server\Resources\SystemResources;
use PHPUnit\Framework\TestCase;

final class SystemResourcesTest extends TestCase
{
    private string $affinityFile = '';

    protected function setUp(): void
    {
        $path = tempnam(
            sys_get_temp_dir(),
            'freedsx_cpu_',
        );
        if ($path === false) {
            self::fail('Could not create a temporary file.');
        }
        $this->affinityFile = $path;
    }

    protected function tearDown(): void
    {
        @unlink($this->affinityFile);
    }

    public function test_it_counts_the_cpus_this_process_may_run_on(): void
    {
        $this->allowCpus('0-2');

        self::assertSame(
            3,
            $this->subjectWithCpus()->cpuCount(),
        );
    }

    public function test_it_reads_the_cpu_count_once(): void
    {
        $this->allowCpus('0-2');
        $subject = $this->subjectWithCpus();
        $subject->cpuCount();

        $this->allowCpus('0-5');

        self::assertSame(
            3,
            $subject->cpuCount(),
        );
    }

    public function test_it_gives_the_open_file_limit_it_was_given(): void
    {
        $openFileLimit = new OpenFileLimit(64);

        self::assertSame(
            $openFileLimit,
            (new SystemResources(openFileLimit: $openFileLimit))->openFileLimit(),
        );
    }

    public function test_it_reads_the_open_file_limit_of_this_process_when_none_is_given(): void
    {
        self::assertSame(
            OpenFileLimit::ofThisProcess()->getSoftLimit(),
            (new SystemResources())->openFileLimit()->getSoftLimit(),
        );
    }

    private function allowCpus(string $list): void
    {
        file_put_contents(
            $this->affinityFile,
            "Cpus_allowed_list:\t{$list}\n",
        );
    }

    private function subjectWithCpus(): SystemResources
    {
        return new SystemResources(new CpuCount(
            $this->affinityFile,
            '/nonexistent/cpu.max',
        ));
    }
}
