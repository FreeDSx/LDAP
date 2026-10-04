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

use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\MetricsDelta;
use FreeDSx\Ldap\Server\Metrics\Rollup\MetricsDeltaMessage;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Process\Channel\ChildChannel;
use FreeDSx\Ldap\Server\ServerRunner\Pcntl\ChildReporter;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class ChildReporterTest extends TestCase
{
    use RequiresExtensionsTrait;

    private ChildChannel $channel;

    private ChildReporter $subject;

    protected function setUp(): void
    {
        $this->requirePcntl();

        $rollup = new OperationRollupCoordinator(new InMemoryMetricsRecorder());
        $this->channel = $rollup->openChannel();

        $this->subject = new ChildReporter(
            $this->channel,
            $rollup,
        );
    }

    public function test_the_parent_keeps_only_the_end_it_reads(): void
    {
        $this->subject->inParent();

        self::assertFalse($this->channel->send(new MetricsDeltaMessage(new MetricsDelta())));
    }

    public function test_a_failed_fork_closes_the_channel(): void
    {
        $this->subject->close();

        self::assertFalse($this->channel->send(new MetricsDeltaMessage(new MetricsDelta())));
    }
}
