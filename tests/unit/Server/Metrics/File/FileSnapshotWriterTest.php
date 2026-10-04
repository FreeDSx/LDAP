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
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotWriter;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotFile;
use FreeDSx\Ldap\Server\Metrics\Snapshot\ConnectionMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\LifecycleMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;
use PHPUnit\Framework\TestCase;

final class FileSnapshotWriterTest extends TestCase
{
    private string $path;

    private FileSnapshotWriter $subject;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/freedsx_metrics_' . uniqid('', true) . '.json';
        $this->subject = new FileSnapshotWriter(SnapshotFile::at($this->path));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->path . '*') ?: [] as $file) {
            @unlink($file);
        }
    }

    public function test_it_writes_the_snapshot_as_decodable_json(): void
    {
        $snapshot = new MetricsSnapshot(
            new LifecycleMetrics(1_000, 0, 0),
            new ConnectionMetrics(3, 9, 1),
        );

        $this->subject->write($snapshot);

        self::assertSame(
            $snapshot->toArray(),
            json_decode(
                (string) file_get_contents($this->path),
                true,
            ),
        );
    }

    public function test_writing_again_overwrites_the_previous_snapshot(): void
    {
        $this->subject->write(new MetricsSnapshot(new LifecycleMetrics(1_000)));
        $this->subject->write(new MetricsSnapshot(new LifecycleMetrics(2_000)));

        self::assertSame(
            (new MetricsSnapshot(new LifecycleMetrics(2_000)))->toArray(),
            json_decode(
                (string) file_get_contents($this->path),
                true,
            ),
        );
    }

    public function test_it_does_not_leave_a_temporary_file_behind(): void
    {
        $this->subject->write(new MetricsSnapshot());

        self::assertSame(
            [$this->path],
            glob($this->path . '*') ?: [],
        );
    }

    public function test_the_temporary_file_never_reuses_a_name_another_user_could_plant(): void
    {
        $planted = $this->path . '.' . getmypid() . '.tmp';
        file_put_contents(
            $planted,
            'planted',
        );

        $this->subject->write(new MetricsSnapshot(new LifecycleMetrics(1_000)));

        self::assertSame(
            'planted',
            file_get_contents($planted),
        );
        self::assertSame(
            (new MetricsSnapshot(new LifecycleMetrics(1_000)))->toArray(),
            json_decode(
                (string) file_get_contents($this->path),
                true,
            ),
        );
    }

    public function test_a_path_that_cannot_be_written_is_reported_rather_than_swallowed(): void
    {
        $subject = new FileSnapshotWriter(SnapshotFile::at(
            sys_get_temp_dir() . '/freedsx_metrics_absent_' . uniqid('', true) . '/snapshot.json',
        ));

        $this->expectException(MetricsSnapshotException::class);

        $subject->write(new MetricsSnapshot());
    }

    public function test_remove_deletes_the_snapshot_file(): void
    {
        $this->subject->write(new MetricsSnapshot());
        self::assertFileExists($this->path);

        $this->subject->remove();

        self::assertFileDoesNotExist($this->path);
    }
}
