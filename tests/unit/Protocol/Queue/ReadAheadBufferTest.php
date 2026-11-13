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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ReadAheadBuffer;
use PHPUnit\Framework\TestCase;

final class ReadAheadBufferTest extends TestCase
{
    private ReadAheadBuffer $subject;

    protected function setUp(): void
    {
        $this->subject = new ReadAheadBuffer();
    }

    public function test_nothing_is_taken_when_no_message_is_held(): void
    {
        self::assertNull($this->subject->take());
    }

    public function test_messages_are_taken_in_the_order_they_were_appended(): void
    {
        $this->subject->append(self::message(1));
        $this->subject->append(self::message(2));

        self::assertSame(
            [1, 2],
            [$this->subject->take()?->getMessageId(), $this->subject->take()?->getMessageId()],
        );
    }

    public function test_a_prepended_message_is_taken_before_the_ones_held(): void
    {
        $this->subject->append(self::message(1));
        $this->subject->prepend(self::message(2));

        self::assertSame(
            2,
            $this->subject->take()?->getMessageId(),
        );
    }

    public function test_it_is_full_once_it_holds_as_many_messages_as_read_ahead_may(): void
    {
        for ($i = 1; $i < 128; $i++) {
            $this->subject->append(self::message($i));
        }
        self::assertFalse($this->subject->isFull());

        $this->subject->append(self::message(128));

        self::assertTrue($this->subject->isFull());
    }

    public function test_it_is_full_once_it_holds_as_many_bytes_as_read_ahead_may(): void
    {
        $this->subject->append(
            self::message(1),
            65_535,
        );
        self::assertFalse($this->subject->isFull());

        $this->subject->append(
            self::message(2),
            1,
        );

        self::assertTrue($this->subject->isFull());
    }

    public function test_its_bytes_are_forgotten_only_once_it_empties(): void
    {
        $this->subject->append(
            self::message(1),
            40_000,
        );
        $this->subject->append(
            self::message(2),
            40_000,
        );

        $this->subject->take();
        self::assertTrue($this->subject->isFull());

        $this->subject->take();
        self::assertFalse($this->subject->isFull());
    }

    private static function message(int $messageId): LdapMessageRequest
    {
        return new LdapMessageRequest(
            $messageId,
            new UnbindRequest(),
        );
    }
}
