<?php

namespace FreeDSx\Ldap\Sync;

final class Session
{
    public const PHASE_DELETE = 0;

    public const PHASE_PRESENT = 1;

    public const STAGE_REFRESH = 0;

    public const STAGE_PERSIST = 1;

    public function __construct(
        private int $stage,
        private ?string $cookie,
        private ?int $phase = null,
    ) {}

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

    public function isPhasePresent(): bool
    {
        return $this->phase === self::PHASE_PRESENT;
    }

    public function isPhaseDelete(): bool
    {
        return $this->phase === self::PHASE_DELETE;
    }


    public function isRefreshing(): bool
    {
        return $this->stage === self::STAGE_REFRESH;
    }

    public function isPersisting(): bool
    {
        return $this->stage === self::STAGE_PERSIST;
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
    public function updateStage(int $stage): self
    {
        $this->stage = $stage;

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
