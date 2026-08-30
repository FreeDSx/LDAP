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

namespace FreeDSx\Ldap\Protocol\Queue;

/**
 * A narrow connection-lifecycle seam handlers use for post-write socket actions without the queue.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ConnectionControl
{
    public function isEncrypted(): bool;

    /**
     * Whether unread input is already buffered.
     */
    public function hasBufferedInput(): bool;

    /**
     * Upgrades the connection. Any input buffered before the upgrade is discarded.
     */
    public function encrypt(): static;

    public function close(): void;
}
