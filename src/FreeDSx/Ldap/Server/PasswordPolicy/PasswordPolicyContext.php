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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;

/**
 * Per-connection holder that bridges the engine and the protocol handler.
 */
final class PasswordPolicyContext
{
    private ?PasswordPolicyOutcome $outcome = null;

    private bool $responseRequested = false;

    public function setOutcome(PasswordPolicyOutcome $outcome): void
    {
        $this->outcome = $outcome;
    }

    /**
     * Whether the client asked for policy information on the request being handled.
     */
    public function setResponseRequested(bool $requested): void
    {
        $this->responseRequested = $requested;
    }

    public function clear(): void
    {
        $this->outcome = null;
    }

    public function getOutcome(): ?PasswordPolicyOutcome
    {
        return $this->outcome;
    }

    /**
     * Convert the stashed outcome into a response control; null when there is nothing to communicate.
     *
     * Withheld unless the client asked, so an unsolicited control cannot report that an account exists and is locked.
     */
    public function buildResponseControl(): ?PwdPolicyResponseControl
    {
        if (!$this->responseRequested) {
            return null;
        }
        if ($this->outcome === null || !$this->outcome->hasResponseControlPayload()) {
            return null;
        }

        return new PwdPolicyResponseControl(
            timeBeforeExpiration: $this->outcome->timeBeforeExpiration,
            graceAuthRemaining: $this->outcome->graceRemaining,
            error: $this->outcome->errorCode,
        );
    }
}
