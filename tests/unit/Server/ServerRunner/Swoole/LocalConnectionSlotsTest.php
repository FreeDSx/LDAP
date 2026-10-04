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

namespace Tests\Unit\FreeDSx\Ldap\Server\ServerRunner\Swoole;

use FreeDSx\Ldap\Server\ServerRunner\Swoole\LocalConnectionSlots;
use PHPUnit\Framework\TestCase;

final class LocalConnectionSlotsTest extends TestCase
{
    private LocalConnectionSlots $subject;

    protected function setUp(): void
    {
        $this->subject = new LocalConnectionSlots();
    }

    public function test_slots_are_refused_once_the_limit_is_reached(): void
    {
        self::assertTrue($this->subject->tryAcquire(2));
        self::assertTrue($this->subject->tryAcquire(2));
        self::assertFalse($this->subject->tryAcquire(2));
    }

    public function test_a_released_slot_can_be_taken_again(): void
    {
        $this->subject->tryAcquire(1);
        $this->subject->release();

        self::assertTrue($this->subject->tryAcquire(1));
    }

    public function test_a_limit_of_zero_never_refuses(): void
    {
        for ($i = 0; $i < 100; $i++) {
            self::assertTrue($this->subject->tryAcquire(0));
        }
    }

    public function test_slots_taken_without_a_limit_count_once_one_is_set(): void
    {
        $this->subject->tryAcquire(0);
        $this->subject->tryAcquire(0);

        self::assertFalse($this->subject->tryAcquire(2));
    }
}
