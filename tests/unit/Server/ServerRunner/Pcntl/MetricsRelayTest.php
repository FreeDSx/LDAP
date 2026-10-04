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

namespace Tests\Unit\FreeDSx\Ldap\Server\ServerRunner\Pcntl;

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Metrics\File\FileSnapshotWriter;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotFile;
use FreeDSx\Ldap\Server\Metrics\File\SnapshotPublisher;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Process\Channel\ChildChannel;
use FreeDSx\Ldap\Server\Process\Child\ChildProcess;
use FreeDSx\Ldap\Server\Process\Child\ReapedChild;
use FreeDSx\Ldap\Server\ServerRunner\Pcntl\MetricsRelay;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

use function mkdir;
use function rmdir;
use function unlink;

final class MetricsRelayTest extends TestCase
{
    use RequiresExtensionsTrait;

    private InMemoryMetricsRecorder $recorder;

    private LoggerInterface&MockObject $logger;

    private SnapshotFile $snapshotFile;

    private MetricsRelay $subject;

    protected function setUp(): void
    {
        $this->requirePcntl();

        $this->recorder = new InMemoryMetricsRecorder();
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->snapshotFile = SnapshotFile::inTempDirectory();

        $this->subject = new MetricsRelay(
            $this->recorder,
            new SnapshotPublisher(
                $this->recorder,
                new FileSnapshotWriter($this->snapshotFile),
            ),
            new OperationRollupCoordinator($this->recorder),
            $this->logger,
        );
    }

    public function test_a_reaped_child_has_its_last_operations_and_close_reason_counted(): void
    {
        $channel = $this->channelReportingOneSearch();

        $this->subject->sweep(
            [new ReapedChild(new ChildProcess(1, $this->createStub(Socket::class), $channel), ConnectionObservation::IdleTimeout)],
            [],
        );

        self::assertSame(
            ['search' => 1],
            $this->recorder->snapshot()->operations->counts,
        );
        self::assertSame(
            1,
            $this->recorder->snapshot()->connections->idleTimeouts,
        );
    }

    public function test_a_running_child_has_the_operations_it_reported_so_far_counted(): void
    {
        $channel = $this->channelReportingOneSearch();

        $this->subject->sweep(
            [],
            [new ChildProcess(1, $this->createStub(Socket::class), $channel)],
        );

        self::assertSame(
            ['search' => 1],
            $this->recorder->snapshot()->operations->counts,
        );
    }

    public function test_a_failing_snapshot_is_reported_once_and_so_is_its_recovery(): void
    {
        $this->logger
            ->expects(self::once())
            ->method('warning');
        $this->logger
            ->expects(self::once())
            ->method('info')
            ->with('Publishing the metrics snapshot recovered.');
        $this->subject->prepare();
        $path = $this->snapshotFile->path();

        try {
            unlink($path);
            mkdir($path);
            $this->subject->serverStarted();
            $this->subject->connectionRejected();

            rmdir($path);
            $this->subject->serverReloaded();
            $this->subject->connectionRejected();
        } finally {
            @rmdir($path);
            $this->subject->remove();
        }
    }

    public function test_no_child_reporter_is_opened_when_nothing_collects_operations(): void
    {
        self::assertNull((new MetricsRelay())->openChildReporter());
    }

    private function channelReportingOneSearch(): ChildChannel
    {
        $channel = $this->subject->openChildReporter()?->channel();
        self::assertNotNull($channel);

        $childRecorder = new InMemoryMetricsRecorder();
        $child = new OperationRollupCoordinator($childRecorder);
        $child->enterChild($channel);
        $childRecorder->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
        $child->finish();

        return $channel;
    }
}
