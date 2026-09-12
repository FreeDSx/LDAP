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
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Snapshot\ConnectionMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\LifecycleMetrics;
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;
use PHPUnit\Framework\TestCase;

final class FileSnapshotProviderTest extends TestCase
{
    private string $path;

    private FileSnapshotProvider $subject;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/freedsx_metrics_' . uniqid('', true) . '.json';
        $this->subject = new FileSnapshotProvider($this->path);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->path)) {
            @unlink($this->path);
        }
    }

    public function test_it_reads_the_snapshot_published_to_the_file(): void
    {
        $snapshot = new MetricsSnapshot(
            new LifecycleMetrics(1_000, 0, 0),
            new ConnectionMetrics(3, 9, 1),
        );
        file_put_contents(
            $this->path,
            (string) json_encode($snapshot->toArray()),
        );

        self::assertEquals(
            $snapshot,
            $this->subject->snapshot(),
        );
    }

    public function test_a_missing_file_is_reported_as_unavailable_rather_than_as_zeroes(): void
    {
        $this->expectException(MetricsSnapshotException::class);

        $this->subject->snapshot();
    }

    public function test_malformed_json_is_reported_as_unavailable_rather_than_as_zeroes(): void
    {
        file_put_contents(
            $this->path,
            '{not valid json',
        );

        $this->expectException(MetricsSnapshotException::class);

        $this->subject->snapshot();
    }

    public function test_non_object_json_is_reported_as_unavailable_rather_than_as_zeroes(): void
    {
        file_put_contents(
            $this->path,
            '"a string"',
        );

        $this->expectException(MetricsSnapshotException::class);

        $this->subject->snapshot();
    }
}
