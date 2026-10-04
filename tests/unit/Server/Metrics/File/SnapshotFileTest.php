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

namespace Tests\Unit\FreeDSx\Ldap\Server\Metrics\File;

use FreeDSx\Ldap\Exception\MetricsSnapshotException;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotFile;
use PHPUnit\Framework\TestCase;

final class SnapshotFileTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/freedsx_snapshot_file_' . uniqid('', true) . '.json';
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function test_a_temp_directory_file_has_no_path_until_it_is_prepared(): void
    {
        $this->expectException(MetricsSnapshotException::class);

        SnapshotFile::inTempDirectory()->path();
    }

    public function test_preparing_a_temp_directory_file_creates_it_for_this_run(): void
    {
        $subject = SnapshotFile::inTempDirectory();

        $subject->prepare();
        $path = $subject->path();
        $subject->remove();

        self::assertSame(
            realpath(sys_get_temp_dir()),
            dirname($path),
        );
        self::assertStringStartsWith(
            'freedsx-ldap-monitor-',
            basename($path),
        );
        self::assertFileDoesNotExist($path);
    }

    public function test_each_temp_directory_file_gets_its_own_name(): void
    {
        $first = SnapshotFile::inTempDirectory();
        $second = SnapshotFile::inTempDirectory();

        $first->prepare();
        $second->prepare();
        $firstPath = $first->path();
        $secondPath = $second->path();
        $first->remove();
        $second->remove();

        self::assertNotSame(
            $firstPath,
            $secondPath,
        );
    }

    public function test_a_configured_path_owned_by_another_user_is_refused(): void
    {
        file_put_contents(
            $this->path,
            '{}',
        );
        $subject = SnapshotFile::at(
            $this->path,
            (int) fileowner($this->path) + 1,
        );

        $this->expectException(MetricsSnapshotException::class);

        $subject->prepare();
    }

    public function test_a_configured_path_owned_by_the_server_user_is_accepted(): void
    {
        file_put_contents(
            $this->path,
            '{}',
        );
        $subject = SnapshotFile::at(
            $this->path,
            (int) fileowner($this->path),
        );

        $subject->prepare();

        self::assertSame(
            $this->path,
            $subject->path(),
        );
    }

    public function test_a_configured_path_that_does_not_exist_yet_is_accepted(): void
    {
        $subject = SnapshotFile::at($this->path);

        $subject->prepare();

        self::assertFileDoesNotExist($this->path);
    }
}
