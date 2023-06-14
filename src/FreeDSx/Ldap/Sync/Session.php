<?php

namespace FreeDSx\Ldap\Sync;

final class Session
{
    public const INITIAL_CONTENT = 0;

    public const CONTENT_UPDATE = 1;

    public const REFRESH_AND_PERSIST = 2;

    public const REFRESH = 3;

    public const PERSIST = 4;

    public function __construct(
        private int $phase,
        private ?string $cookie,
    )
    {}

    /**
     * The phase currently in progress for the sync session. One of:
     *
     *   - {@see self::INITIAL_CONTENT}
     *   - {@see self::CONTENT_UPDATE}
     *   - {@see self::REFRESH_AND_PERSIST}
     *   - {@see self::REFRESH}
     *   - {@see self::PERSIST}
     *
     */
    public function getPhase(): int
    {
        return $this->phase;
    }

    /**
     * The cookie that represents this sync session.
     */
    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    /**
     * @internal
     */
    public function updatePhase(int $phase): self
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
