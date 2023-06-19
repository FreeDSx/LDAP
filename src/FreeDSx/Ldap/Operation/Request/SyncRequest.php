<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Operation\Request;

use Closure;

class SyncRequest extends SearchRequest
{
    private ?Closure $syncIdSetHandler = null;

    private ?Closure $phaseChangeHandler = null;

    public function useSyncIdSetHandler(?Closure $syncIdSetHandler): self
    {
        $this->syncIdSetHandler = $syncIdSetHandler;

        return $this;
    }

    public function getSyncIdSetHandler(): ?Closure
    {
        return $this->syncIdSetHandler;
    }

    public function usePhaseChangeHandler(?Closure $phaseChangeHandler): self
    {
        $this->phaseChangeHandler = $phaseChangeHandler;

        return $this;
    }

    public function getPhaseChangeHandler(): ?Closure
    {
        return $this->phaseChangeHandler;
    }
}
