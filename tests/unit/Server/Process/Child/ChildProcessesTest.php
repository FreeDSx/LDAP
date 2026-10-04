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

use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Process\Child\ChildExitCode;
use FreeDSx\Ldap\Server\Process\Child\ChildProcess;
use FreeDSx\Ldap\Server\Process\Child\ChildProcesses;
use FreeDSx\Ldap\Server\Process\Child\ReapedChild;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

use function microtime;
use function pcntl_fork;
use function pcntl_waitpid;
use function posix_kill;
use function sleep;
use function usleep;

final class ChildProcessesTest extends TestCase
{
    use RequiresExtensionsTrait;

    private ChildProcesses $subject;

    /**
     * @var list<int>
     */
    private array $running = [];

    protected function setUp(): void
    {
        $this->requirePcntl();
        $this->requirePosix();

        $this->subject = new ChildProcesses();
    }

    protected function tearDown(): void
    {
        foreach ($this->running as $pid) {
            posix_kill(
                $pid,
                SIGKILL,
            );
            pcntl_waitpid(
                $pid,
                $status,
            );
        }
    }

    public function test_an_exited_child_is_reaped_with_the_close_reason_its_exit_code_reports(): void
    {
        $this->subject->add($this->childExitingWith(ChildExitCode::IdleTimeout->value));

        $reaped = $this->reapWithin(5.0);

        self::assertSame(
            ConnectionObservation::IdleTimeout,
            $reaped->closeReason,
        );
        self::assertTrue($this->subject->isEmpty());
    }

    public function test_a_child_still_running_is_left_in_the_table(): void
    {
        $child = $this->childStillRunning();
        $this->subject->add($child);

        self::assertSame(
            [],
            $this->subject->reapExited(),
        );
        self::assertSame(
            [$child],
            $this->subject->all(),
        );
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

    private function childExitingWith(int $code): ChildProcess
    {
        $pid = pcntl_fork();
        if ($pid === 0) {
            exit($code);
        }

        return new ChildProcess(
            $pid,
            $this->createStub(Socket::class),
        );
    }

    private function childStillRunning(): ChildProcess
    {
        $pid = pcntl_fork();
        if ($pid === 0) {
            sleep(30);
            exit(0);
        }
        $this->running[] = $pid;

        return new ChildProcess(
            $pid,
            $this->createStub(Socket::class),
        );
    }

    /**
     * The child exits on its own schedule, so it is reaped as soon as it has.
     */
    private function reapWithin(float $seconds): ReapedChild
    {
        $deadline = microtime(true) + $seconds;

        while (microtime(true) < $deadline) {
            $reaped = $this->subject->reapExited();
            if ($reaped !== []) {
                return $reaped[0];
            }

            usleep(10_000);
        }

        self::fail('The child was never reaped.');
    }
}
