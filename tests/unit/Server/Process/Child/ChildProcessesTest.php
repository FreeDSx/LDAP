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

use FreeDSx\Ldap\Server\Process\Child\ChildProcess;
use FreeDSx\Ldap\Server\Process\Child\ChildProcesses;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\TestCase;

final class ChildProcessesTest extends TestCase
{
    private ChildProcesses $subject;

    protected function setUp(): void
    {
        $this->subject = new ChildProcesses();
    }

    public function test_a_fork_releases_its_copies_of_the_others_connections_without_ending_them(): void
    {
        $socket = $this->createMock(Socket::class);
        $socket
            ->expects(self::once())
            ->method('close')
            ->with(false);
        $this->subject->add(new ChildProcess(
            1,
            $socket,
        ));

        $this->subject->releaseInherited();

        self::assertCount(
            0,
            $this->subject,
        );
    }
}
