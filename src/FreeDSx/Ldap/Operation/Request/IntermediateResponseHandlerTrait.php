<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Operation\Request;

use Closure;

/**
 * Used for requests that want to support Intermediate Responses. This still requires that the protocol handlers have
 * some logic processing this and handing them off.
 */
trait IntermediateResponseHandlerTrait
{
    private ?Closure $intermediateResponseHandler = null;

    /**
     * Set the anonymous function that will handle the IntermediateResponse for this request. The function will receive
     * the full LdapMessageResponse with the IntermediateResponse object in it. It is up to the handler how to process
     * it.
     */
    public function useIntermediateResponseHandler(?Closure $intermediateResponseHandler): self
    {
        $this->intermediateResponseHandler = $intermediateResponseHandler;

        return $this;
    }

    public function getIntermediateResponseHandler(): ?Closure
    {
        return $this->intermediateResponseHandler;
    }
}
