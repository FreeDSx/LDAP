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

use FreeDSx\Ldap\Server\Backend\Write\PasswordPolicyWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\NullSystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriter;
use FreeDSx\Ldap\Server\Backend\Write\SystemChange\SystemChangeWriterInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\ServerOptions;

/**
 * Builds the password-policy write-enforcement components from shared services plus per-connection state.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordPolicyComponentFactory
{
    public function __construct(
        private WritableLdapBackendInterface $backend,
        private ServerOptions $options,
        private WriteOperationDispatcher $writeDispatcher,
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
            $guard,
            $this->makeSystemChangeWriter(),
        );
    }

    public function makeChangeGuard(
        EventLogger $eventLogger,
        ?PasswordPolicyContext $passwordPolicyContext,
    ): ?PasswordPolicyChangeGuard {
        if ($passwordPolicyContext === null || !$this->options->isPasswordPolicyEnabled()) {
            return null;
        }

        return new PasswordPolicyChangeGuard(
            $this->passwordPolicyEngine,
            $this->policyResolver,
            $passwordPolicyContext,
            $eventLogger,
        );
    }

    /**
     * A read-only server has nothing to write the operational changes a policy decision produces back to.
     */
    private function makeSystemChangeWriter(): SystemChangeWriterInterface
    {
        if ($this->options->isReadOnly()) {
            return new NullSystemChangeWriter();
        }

        return new SystemChangeWriter($this->writeDispatcher);
    }
}
