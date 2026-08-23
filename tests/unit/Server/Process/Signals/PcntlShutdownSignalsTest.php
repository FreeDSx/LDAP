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

namespace Tests\Unit\FreeDSx\Ldap\Server\Process\Signals;

use FreeDSx\Ldap\Server\Process\Signals\PcntlShutdownSignals;
use FreeDSx\Ldap\Server\Process\Signals\ShutdownSignalsInterface;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class PcntlShutdownSignalsTest extends TestCase
{
    use RequiresExtensionsTrait;

    private ShutdownSignalsInterface $subject;

    protected function setUp(): void
    {
        // pcntl_* is ext-pcntl; posix_kill/posix_getpid (used to raise the signal) is ext-posix.
        $this->requirePcntl();
        $this->requirePosix();

        $this->subject = new PcntlShutdownSignals();
    }

    protected function tearDown(): void
    {
        if (!extension_loaded('pcntl')) {
            return;
        }

        pcntl_signal(SIGINT, SIG_DFL);
        pcntl_signal(SIGTERM, SIG_DFL);
    }

    public function test_the_handler_runs_on_a_termination_signal(): void
    {
        $fired = false;
        $this->subject->onShutdown(function () use (&$fired): void {
            $fired = true;
        });

        posix_kill(posix_getpid(), SIGTERM);
        pcntl_signal_dispatch();

        self::assertTrue($fired);
    }
}
