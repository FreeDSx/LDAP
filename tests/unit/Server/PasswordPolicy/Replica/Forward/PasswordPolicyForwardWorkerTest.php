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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward;

use FreeDSx\Ldap\Exception\ForwardStateException;
use FreeDSx\Ldap\Server\Clock\Sleeper\BackoffSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Config\ReconnectBackoff;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\PasswordPolicyForwarder;
use FreeDSx\Ldap\Server\PasswordPolicy\Replica\Forward\PasswordPolicyForwardWorker;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyForwardWorkerTest extends TestCase
{
    private PasswordPolicyForwarder&MockObject $forwarder;

    /**
     * @var list<float>
     */
    private array $slept;

    private PasswordPolicyForwardWorker $subject;

    protected function setUp(): void
    {
        $this->forwarder = $this->createMock(PasswordPolicyForwarder::class);
        $this->slept = [];

        // Stop after each sleep so run() executes exactly one loop iteration per test.
        $sleeper = $this->createMock(SleeperInterface::class);
        $sleeper->method('sleep')
            ->willReturnCallback(function (float $seconds): void {
                $this->slept[] = $seconds;
                $this->subject->stop();
            });

        $this->subject = new PasswordPolicyForwardWorker(
            $this->forwarder,
            $sleeper,
            new BackoffSleeper(
                new ReconnectBackoff(),
                $sleeper,
            ),
        );
    }

    public function test_run_drains_then_sleeps_the_poll_interval(): void
    {
        $this->forwarder
            ->expects(self::once())
            ->method('forwardOnce')
            ->willReturn(1);

        $this->subject->run();

        self::assertSame(
            [PasswordPolicyForwardWorker::DEFAULT_INTERVAL_SECONDS],
            $this->slept,
        );
    }

    public function test_run_backs_off_on_a_delivery_failure(): void
    {
        $this->forwarder
            ->method('forwardOnce')
            ->willThrowException(new ForwardStateException('primary is unreachable'));

        $this->subject->run();

        self::assertSame(
            [1.0],
            $this->slept,
        );
    }
}
