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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer;

use Swoole\Coroutine;

/**
 * Tracks whether the caller is running inside the serialized writer's open transaction.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class WriteScope
{
    /**
     * Coroutine that opened the outermost write, or null when none is open; -1 when there is no coroutine at all.
     */
    private ?int $owner = null;

    private int $depth = 0;

    public function enter(): void
    {
        $this->owner = Coroutine::getCid();
        $this->depth++;
    }

    public function leave(): void
    {
        $this->depth--;

        if ($this->depth === 0) {
            $this->owner = null;
        }
    }

    /**
     * True only on the coroutine holding the write, so a concurrent reader is never routed into its transaction.
     */
    public function isActive(): bool
    {
        return $this->depth > 0
            && $this->owner === Coroutine::getCid();
    }
}
