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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\ServerRunner\Swoole\SharedConnectionSlots;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class SharedConnectionSlotsTest extends TestCase
{
    use RequiresExtensionsTrait;

    private SharedConnectionSlots $subject;

    protected function setUp(): void
    {
        $this->requireSwoole();

        $this->subject = new SharedConnectionSlots(2);
    }

    public function test_the_limit_counts_the_slots_every_worker_holds(): void
    {
        $this->subject->claimWorker(0);
        $this->subject->tryAcquire(2);
        $this->subject->claimWorker(1);

        self::assertTrue($this->subject->tryAcquire(2));
        self::assertFalse($this->subject->tryAcquire(2));
    }

    public function test_a_refused_slot_is_not_left_counted(): void
    {
        $this->subject->claimWorker(0);
        $this->subject->tryAcquire(1);
        $this->subject->tryAcquire(1);
        $this->subject->release();

        self::assertTrue($this->subject->tryAcquire(1));
    }

    public function test_a_respawned_worker_frees_the_slots_its_predecessor_held(): void
    {
        $this->subject->claimWorker(0);
        $this->subject->tryAcquire(3);
        $this->subject->claimWorker(1);
        $this->subject->tryAcquire(3);
        $this->subject->tryAcquire(3);

        $this->subject->claimWorker(1);

        self::assertTrue($this->subject->tryAcquire(3));
        self::assertTrue($this->subject->tryAcquire(3));
        self::assertFalse($this->subject->tryAcquire(3));
    }

    public function test_a_limit_of_zero_never_refuses(): void
    {
        $this->subject->claimWorker(0);

        for ($i = 0; $i < 100; $i++) {
            self::assertTrue($this->subject->tryAcquire(0));
        }
    }

    public function test_a_worker_id_without_slots_is_refused(): void
    {
        $this->expectException(RuntimeException::class);

        $this->subject->claimWorker(5);
    }
}
