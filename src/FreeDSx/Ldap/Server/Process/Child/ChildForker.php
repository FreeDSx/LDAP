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

namespace FreeDSx\Ldap\Server\Process\Child;

use Closure;
use FreeDSx\Ldap\Exception\ForkFailedException;

use function pcntl_fork;
use function pcntl_get_last_error;
use function pcntl_sigprocmask;
use function pcntl_strerror;
use function sprintf;

use const SIG_BLOCK;
use const SIG_UNBLOCK;
use const SIGHUP;
use const SIGINT;
use const SIGQUIT;
use const SIGTERM;
use const SIGUSR1;

/**
 * Starts a child process with signals held blocked across the fork.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ChildForker
{
    /**
     * Every signal a server process or its children handle.
     */
    private const BLOCKED_SIGNALS = [
        SIGINT,
        SIGTERM,
        SIGQUIT,
        SIGHUP,
        SIGUSR1,
    ];

    /**
     * Runs the child's work in a new process and the parent's with the child's PID.
     *
     * @param Closure(): void $inChild must call unblockSignals() once its own handlers are installed.
     * @param Closure(int): void $inParent runs before the signals are unblocked.
     * @throws ForkFailedException
     */
    public function start(
        Closure $inChild,
        Closure $inParent,
    ): void {
        pcntl_sigprocmask(
            SIG_BLOCK,
            self::BLOCKED_SIGNALS,
        );

        $pid = @pcntl_fork();
        if ($pid === 0) {
            self::runChild($inChild);
        }

        try {
            if ($pid === -1) {
                throw new ForkFailedException(sprintf(
                    'Unable to fork a child process: %s',
                    pcntl_strerror(pcntl_get_last_error()),
                ));
            }
            $inParent($pid);
        } finally {
            $this->unblockSignals();
        }
    }

    /**
     * Delivers the signals held since the fork.
     */
    public function unblockSignals(): void
    {
        pcntl_sigprocmask(
            SIG_UNBLOCK,
            self::BLOCKED_SIGNALS,
        );
    }

    /**
     * @param Closure(): void $inChild
     */
    private static function runChild(Closure $inChild): never
    {
        try {
            $inChild();
        } finally {
            // A child never returns into the parent's code, even when its work throws.
            exit(1);
        }
    }
}
