<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Operation\Request;

use Closure;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;

class SyncRequest extends SearchRequest
{
    private ?Closure $syncIdSetHandler = null;

    private ?Closure $phaseChangeHandler = null;

    public function __construct(
        ?FilterInterface $filter = null,
        string|Attribute ...$attributes
    ) {
        parent::__construct(
            $filter ?? Filters::present('objectClass'),
            ...$attributes,
        );
    }

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
