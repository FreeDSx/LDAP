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

use FreeDSx\Ldap\Server\Process\Signals\SwooleShutdownSignals;
use PHPUnit\Framework\TestCase;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class SwooleShutdownSignalsTest extends TestCase
{
    use RequiresExtensionsTrait;

    protected function setUp(): void
    {
        $this->requireSwoole();
        $this->requirePosix();
    }

    public function test_the_handler_runs_on_a_termination_signal(): void
    {
        $fired = false;

        Coroutine\run(function () use (&$fired): void {
            $channel = new Channel(1);
            (new SwooleShutdownSignals())->onShutdown(function () use ($channel): void {
                $channel->push(true);
            });

            posix_kill(posix_getpid(), SIGTERM);
            $fired = $channel->pop(2.0) === true;
        });

        self::assertTrue($fired);
    }
}
