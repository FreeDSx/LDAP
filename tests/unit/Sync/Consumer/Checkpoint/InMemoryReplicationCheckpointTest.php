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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Consumer\Checkpoint;

use FreeDSx\Ldap\Sync\Consumer\Checkpoint\InMemoryReplicationCheckpoint;
use FreeDSx\Ldap\Sync\Consumer\Checkpoint\ReplicationCheckpointInterface;
use PHPUnit\Framework\TestCase;

final class InMemoryReplicationCheckpointTest extends TestCase
{
    private ReplicationCheckpointInterface $subject;

    protected function setUp(): void
    {
        $this->subject = new InMemoryReplicationCheckpoint();
    }

    public function test_read_returns_null_before_anything_is_written(): void
    {
        self::assertNull($this->subject->read());
    }

    public function test_write_then_read_round_trips_the_cookie(): void
    {
        $this->subject->write('cookie-123');

        self::assertSame(
            'cookie-123',
            $this->subject->read(),
        );
    }

    public function test_clear_forgets_the_cookie(): void
    {
        $this->subject->write('cookie-123');

        $this->subject->clear();

        self::assertNull($this->subject->read());
    }
}
