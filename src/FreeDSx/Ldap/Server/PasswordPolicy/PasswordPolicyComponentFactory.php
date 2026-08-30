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

use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\PasswordPolicyWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;

/**
 * Builds the password-policy write-enforcement components from shared services plus per-connection state.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordPolicyComponentFactory
{
    public function __construct(
        private ReadBackendInterface $backend,
        private WriteHandlerInterface $writeDispatcher,
        private PasswordPolicyEngine $passwordPolicyEngine,
        private PasswordPolicyResolver $policyResolver,
    ) {}

    public function makeWriteHandler(
        EventLogger $eventLogger,
        ?PasswordPolicyContext $passwordPolicyContext,
    ): ?PasswordPolicyWriteHandler {
        $guard = $this->makeChangeGuard(
            $eventLogger,
            $passwordPolicyContext,
        );

        if ($guard === null) {
            return null;
        }

        return new PasswordPolicyWriteHandler(
            $this->backend,
            $this->writeDispatcher,
            $guard,
        );
    }

    /**
     * The write entry point for a connection, wrapped in policy enforcement where policy is active.
     */
    public function makeWriteDispatcher(
        EventLogger $eventLogger,
        ?PasswordPolicyContext $passwordPolicyContext,
    ): WriteHandlerInterface {
        return $this->makeWriteHandler(
            $eventLogger,
            $passwordPolicyContext,
        ) ?? $this->writeDispatcher;
    }

    public function makeChangeGuard(
        EventLogger $eventLogger,
        ?PasswordPolicyContext $passwordPolicyContext,
    ): ?PasswordPolicyChangeGuard {
        if ($passwordPolicyContext === null) {
            return null;
        }

        return new PasswordPolicyChangeGuard(
            $this->passwordPolicyEngine,
            $this->policyResolver,
            $passwordPolicyContext,
            $eventLogger,
        );
    }
}
