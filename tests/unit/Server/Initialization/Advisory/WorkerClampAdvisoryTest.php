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

namespace Tests\Unit\FreeDSx\Ldap\Server\Initialization\Advisory;

use FreeDSx\Ldap\Server\Initialization\Advisory\WorkerClampAdvisory;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\WorkerLimit;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class WorkerClampAdvisoryTest extends TestCase
{
    private WorkerLimit&MockObject $limit;

    private WorkerClampAdvisory $subject;

    protected function setUp(): void
    {
        $this->limit = $this->createMock(WorkerLimit::class);
        $this->limit
            ->method('requested')
            ->willReturn(4);
        $this->subject = new WorkerClampAdvisory($this->limit);
    }

    public function test_it_warns_with_what_limits_the_workers_and_how_many_were_requested(): void
    {
        $this->limit
            ->method('reason')
            ->willReturn(ConcurrencyLimitReason::UnixSocket);

        self::assertEquals(
            [
                InitializationWarning::concurrencyLimited(
                    ConcurrencyLimitReason::UnixSocket,
                    ['requested_workers' => 4],
                ),
            ],
            $this->subject->warnings(),
        );
    }

    public function test_it_does_not_warn_when_nothing_limits_the_workers(): void
    {
        $this->limit
            ->method('reason')
            ->willReturn(null);

        self::assertSame(
            [],
            $this->subject->warnings(),
        );
    }
}
