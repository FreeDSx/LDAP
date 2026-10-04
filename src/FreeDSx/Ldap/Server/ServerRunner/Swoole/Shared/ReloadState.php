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

namespace FreeDSx\Ldap\Server\ServerRunner\Swoole\Shared;

use Swoole\Atomic;

/**
 * Whether any worker has applied a reload since the server started, kept in shared memory.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ReloadState
{
    private Atomic $reloaded;

    /**
     * Must be built before a pool forks, so every worker shares the same flag.
     */
    public function __construct()
    {
        $this->reloaded = new Atomic();
    }

    public function hasReloaded(): bool
    {
        return $this->reloaded->get() > 0;
    }

    public function markReloaded(): void
    {
        $this->reloaded->set(1);
    }
}
