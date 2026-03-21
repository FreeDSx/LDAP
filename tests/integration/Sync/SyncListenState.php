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

namespace Tests\Integration\FreeDSx\Ldap\Sync;

/**
 * Simple DTO for testing.
 *
 * @internal
 */
final class SyncListenState
{
    public bool $seenRefreshPhase = false;

    public bool $seenPersistPhase = false;

    public bool $signaled = false;
}
