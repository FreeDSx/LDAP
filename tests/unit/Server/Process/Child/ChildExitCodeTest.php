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

namespace Tests\Unit\FreeDSx\Ldap\Server\Process\Child;

use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Process\Child\ChildExitCode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class ChildExitCodeTest extends TestCase
{
    use RequiresExtensionsTrait;

    /**
     * @return iterable<string, array{ConnectionObservation}>
     */
    public static function countedCloseReasonProvider(): iterable
    {
        yield 'a write timeout' => [ConnectionObservation::WriteTimeout];
        yield 'an idle timeout' => [ConnectionObservation::IdleTimeout];
        yield 'an oversized request' => [ConnectionObservation::RequestSizeExceeded];
        yield 'a protocol error' => [ConnectionObservation::ProtocolError];
    }

    #[DataProvider('countedCloseReasonProvider')]
    public function test_a_counted_close_reason_survives_the_exit_code_round_trip(ConnectionObservation $closeReason): void
    {
        $this->requirePcntl();

        self::assertSame(
            $closeReason,
            ChildExitCode::closeReasonFor(ChildExitCode::forCloseReason($closeReason) << 8),
        );
    }

    public function test_a_close_reason_the_parent_does_not_count_exits_with_zero(): void
    {
        self::assertSame(
            0,
            ChildExitCode::forCloseReason(ConnectionObservation::Opened),
        );
        self::assertSame(
            0,
            ChildExitCode::forCloseReason(null),
        );
    }

    public function test_an_ordinary_exit_reports_no_close_reason(): void
    {
        $this->requirePcntl();

        self::assertNull(ChildExitCode::closeReasonFor(0));
    }

    public function test_a_child_ended_by_a_signal_reports_no_close_reason(): void
    {
        $this->requirePcntl();

        self::assertNull(ChildExitCode::closeReasonFor(SIGKILL));
    }
}
