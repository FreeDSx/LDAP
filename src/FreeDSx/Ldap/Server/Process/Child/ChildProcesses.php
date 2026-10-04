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

use Countable;

use function count;
use function pcntl_waitpid;

use const WNOHANG;

/**
 * The connection children a forking runner has started and not yet reaped.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ChildProcesses implements Countable
{
    /**
     * @var list<ChildProcess>
     */
    private array $children = [];

    public function add(ChildProcess $child): void
    {
        $this->children[] = $child;
    }

    public function count(): int
    {
        return count($this->children);
    }

    public function isEmpty(): bool
    {
        return $this->children === [];
    }

    /**
     * @return list<ChildProcess>
     */
    public function all(): array
    {
        return $this->children;
    }

    /**
     * Removes and returns the children that have exited, without waiting on any still running.
     *
     * @return list<ReapedChild>
     */
    public function reapExited(): array
    {
        $running = [];
        $reaped = [];

        foreach ($this->children as $child) {
            $status = 0;
            $result = pcntl_waitpid(
                $child->getPid(),
                $status,
                WNOHANG,
            );

            if ($result === 0) {
                $running[] = $child;

                continue;
            }

            // A failed wait has no status to read, but the child is gone all the same.
            $reaped[] = new ReapedChild(
                $child,
                $result > 0
                    ? ChildExitCode::closeReasonFor($status)
                    : null,
            );
        }
        $this->children = $running;

        return $reaped;
    }

    /**
     * A fresh fork drops its copies of the others' connections, so it neither leaks them nor ends them when it exits.
     */
    public function releaseInherited(): void
    {
        foreach ($this->children as $child) {
            $child->getChannel()?->close();
            $child->releaseSocket();
        }

        $this->children = [];
    }
}
