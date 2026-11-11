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

use FreeDSx\Ldap\Server\Process\Channel\ChildChannel;

use function posix_kill;

readonly class ChildProcess
{
    public function __construct(
        private int $pid,
        private ?ChildChannel $channel = null,
    ) {}

    public function getPid(): int
    {
        return $this->pid;
    }

    public function getChannel(): ?ChildChannel
    {
        return $this->channel;
    }

    public function signal(int $signal): void
    {
        posix_kill(
            $this->pid,
            $signal,
        );
    }
}
