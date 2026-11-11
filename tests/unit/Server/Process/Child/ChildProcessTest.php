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

use FreeDSx\Ldap\Server\Process\Channel\ChildChannel;
use FreeDSx\Ldap\Server\Process\Child\ChildProcess;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresOperatingSystemTrait;
use Tests\Support\FreeDSx\Ldap\Server\Process\Channel\FakeChannelMessageFactory;

final class ChildProcessTest extends TestCase
{
    use RequiresOperatingSystemTrait;

    private ChildProcess $subject;

    protected function setUp(): void
    {
        $this->subject = new ChildProcess(9001);
    }

    public function test_it_should_get_the_pid(): void
    {
        self::assertSame(
            9001,
            $this->subject->getPid(),
        );
    }

    public function test_the_channel_is_null_by_default(): void
    {
        self::assertNull($this->subject->getChannel());
    }

    public function test_it_should_get_the_channel_when_present(): void
    {
        $this->requireUnix('UNIX socket pairs are unavailable on Windows; the channel is Linux/PCNTL-only.');

        $channel = ChildChannel::create(new FakeChannelMessageFactory());

        $subject = new ChildProcess(
            9002,
            $channel,
        );

        self::assertSame(
            $channel,
            $subject->getChannel(),
        );
    }
}
