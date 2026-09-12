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

namespace Tests\Unit\FreeDSx\Ldap\Server\Clock\Sleeper;

use FreeDSx\Ldap\Server\Clock\Sleeper\BackoffSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Config\ReconnectBackoff;
use PHPUnit\Framework\TestCase;

final class BackoffSleeperTest extends TestCase
{
    /**
     * @var list<float>
     */
    private array $slept;

    private BackoffSleeper $subject;

    protected function setUp(): void
    {
        $this->slept = [];
        $sleeper = $this->createMock(SleeperInterface::class);
        $sleeper->method('sleep')
            ->willReturnCallback(function (float $seconds): void {
                $this->slept[] = $seconds;
            });

        $this->subject = new BackoffSleeper(
            new ReconnectBackoff(
                baseSeconds: 1.0,
                maxSeconds: 4.0,
            ),
            $sleeper,
        );
    }

    public function test_it_starts_at_the_initial_delay(): void
    {
        self::assertSame(
            1.0,
            $this->subject->delay(),
        );
    }

    public function test_wait_sleeps_the_current_delay_then_widens_it(): void
    {
        $this->subject->wait();

        self::assertSame(
            [1.0],
            $this->slept,
        );
        self::assertSame(
            2.0,
            $this->subject->delay(),
        );
    }

    public function test_repeated_waits_double_up_to_the_ceiling(): void
    {
        $this->subject->wait();
        $this->subject->wait();
        $this->subject->wait();
        $this->subject->wait();

        self::assertSame(
            [1.0, 2.0, 4.0, 4.0],
            $this->slept,
        );
    }

    public function test_reset_returns_to_the_initial_delay(): void
    {
        $this->subject->wait();
        $this->subject->wait();
        $this->subject->reset();

        self::assertSame(
            1.0,
            $this->subject->delay(),
        );
    }
}
