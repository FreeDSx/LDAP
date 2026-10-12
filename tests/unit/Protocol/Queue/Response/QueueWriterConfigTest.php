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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Protocol\Queue\Response\QueueWriterConfig;
use PHPUnit\Framework\TestCase;

final class QueueWriterConfigTest extends TestCase
{
    public function test_a_poll_is_due_once_the_interval_is_reached(): void
    {
        $subject = new QueueWriterConfig(signalInterval: 3);

        self::assertFalse($subject->isPollDue(2));
        self::assertTrue($subject->isPollDue(3));
    }

    public function test_a_poll_is_never_due_when_polling_is_disabled(): void
    {
        $subject = new QueueWriterConfig(flushPerMessage: true);

        self::assertFalse($subject->isPollDue(1));
        self::assertFalse($subject->isPollDue(100));
    }

    public function test_a_stream_is_not_persistent_by_default(): void
    {
        self::assertFalse((new QueueWriterConfig(signalInterval: 1))->persistent);
    }

    public function test_a_persistent_stream_must_poll_for_signals(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new QueueWriterConfig(
            flushPerMessage: true,
            persistent: true,
        );
    }
}
