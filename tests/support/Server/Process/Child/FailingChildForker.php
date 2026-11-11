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

namespace Tests\Support\FreeDSx\Ldap\Server\Process\Child;

use Closure;
use FreeDSx\Ldap\Exception\ForkFailedException;
use FreeDSx\Ldap\Server\Process\Child\ChildForker;

/**
 * Fails one chosen start without forking and starts every other child for real.
 */
final class FailingChildForker extends ChildForker
{
    private int $starts = 0;

    /**
     * @param int $failingStart the start to fail, counted from 1.
     */
    public function __construct(private readonly int $failingStart) {}

    public function start(
        Closure $inChild,
        Closure $inParent,
        array $blockedSignals,
    ): void {
        $this->starts++;
        if ($this->starts === $this->failingStart) {
            throw new ForkFailedException('Unable to fork a child process: a scripted failure');
        }

        parent::start(
            $inChild,
            $inParent,
            $blockedSignals,
        );
    }
}
