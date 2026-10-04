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

use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotWriter;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotFile;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotPublisher;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use PHPUnit\Framework\TestCase;

final class SnapshotPublisherTest extends TestCase
{
    private string $path;

    private InMemoryMetricsRecorder $source;

    private SnapshotPublisher $subject;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/freedsx_metrics_' . uniqid('', true) . '.json';
        $this->source = new InMemoryMetricsRecorder();
        $this->subject = new SnapshotPublisher(
            $this->source,
            new FileSnapshotWriter(SnapshotFile::at($this->path)),
        );
    }

    protected function tearDown(): void
    {
        foreach (glob($this->path . '*') ?: [] as $file) {
            @unlink($file);
        }
    }

    public function test_publish_writes_the_source_snapshot_to_the_file(): void
    {
        $this->source->serverStarted(1_000);
        $this->source->connectionObserved(ConnectionObservation::Opened);
        $this->source->connectionObserved(ConnectionObservation::Opened);

        $this->subject->publish();

        self::assertEquals(
            $this->source->snapshot(),
            (new FileSnapshotProvider(SnapshotFile::at($this->path)))->snapshot(),
        );
    }

    public function test_publish_overwrites_with_the_latest_snapshot(): void
    {
        $this->subject->publish();
        $this->source->connectionObserved(ConnectionObservation::Opened);
        $this->subject->publish();

        self::assertSame(
            1,
            (new FileSnapshotProvider(SnapshotFile::at($this->path)))->snapshot()->connections->active,
        );
    }

    public function test_remove_deletes_the_published_file(): void
    {
        $this->subject->publish();
        self::assertFileExists($this->path);

        $this->subject->remove();

        self::assertFileDoesNotExist($this->path);
    }
}
