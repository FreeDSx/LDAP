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

namespace FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Control\Sync\SyncRequestControl;

final class Session
{
    public const PHASE_DELETE = 0;

    public const PHASE_PRESENT = 1;

    public const MODE_POLL = SyncRequestControl::MODE_REFRESH_ONLY;

    public const MODE_LISTEN = SyncRequestControl::MODE_REFRESH_AND_PERSIST;

    public function __construct(
        private readonly int $mode,
        private ?string $cookie,
        private ?int $phase = null,
    ) {
    }

    /**
     * The cookie that represents this sync session.
     */
    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    /**
     * The phase currently in progress for the sync session. One of:
     *
     *   - {@see self::PHASE_DELETE}
     *   - {@see self::PHASE_PRESENT}
     *
     * May return null if neither of those phases are currently active.
     */
    public function getPhase(): ?int
    {
        return $this->phase;
    }

    /**
     * The mode of the session. One of:
     *
     *   - {@see self::MODE_POLL}
     *   - {@see self::MODE_LISTEN}
     */
    public function getMode(): int
    {
        return $this->mode;
    }

    /**
     * @internal
     */
    public function updatePhase(?int $phase): self
    {
        $this->phase = $phase;

        return $this;
    }

    /**
     * @internal
     */
    public function updateCookie(?string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }
}
