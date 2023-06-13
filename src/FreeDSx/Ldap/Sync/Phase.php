<?php

namespace FreeDSx\Ldap\Sync;

final class Phase
{
    public const INITIAL_CONTENT = 0;

    public const CONTENT_UPDATE = 1;

    public const REFRESH_AND_PERSIST = 2;

    public const REFRESH = 3;

    public const PERSIST = 4;

    public function __construct(
        private readonly int $phase,
        private readonly bool $isComplete,
    )
    {}

    /**
     * The phase currently in progress. One of:
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
     * Whether the current phase is complete.
     */
    public function isComplete(): bool
    {
        return $this->isComplete;
    }
}
