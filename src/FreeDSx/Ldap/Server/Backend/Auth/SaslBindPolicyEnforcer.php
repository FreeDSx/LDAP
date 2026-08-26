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

namespace FreeDSx\Ldap\Server\Backend\Auth;

use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Drives the bind guard for the SASL flow, where the identity is only known once the exchange completes.
 */
final readonly class SaslBindPolicyEnforcer
{
    public function __construct(
        private BindNameResolverInterface $nameResolver,
        private ReadBackendInterface $backend,
        private PasswordPolicyResolver $resolver,
        private PasswordPolicyBindGuard $guard,
        private PasswordPolicyContext $context,
    ) {}

    public function recordFailure(?string $username): void
    {
        if ($username === null) {
            return;
        }

        $entry = $this->nameResolver->resolve(
            $username,
            $this->backend,
        );
        $attempt = $entry !== null
            ? $this->attemptFor($username, $entry)
            : null;
        if ($attempt === null) {
            return;
        }

        $this->guard->recordFailure($attempt);
    }

    /**
     * @throws OperationException when the account is locked or the password is expired without grace.
     */
    public function enforceSuccess(
        string $username,
        Dn $resolvedDn,
    ): void {
        $entry = $this->backend->get($resolvedDn);
        $attempt = $entry !== null
            ? $this->attemptFor($username, $entry)
            : null;
        if ($attempt === null) {
            return;
        }

        $this->guard->preBind($attempt);
        $this->guard->recordSuccess($attempt);
    }

    /**
     * Whether the just-enforced bind flagged that the password must be changed.
     */
    public function mustChangePassword(): bool
    {
        return $this->context->getOutcome()?->errorCode === PwdPolicyError::CHANGE_AFTER_RESET;
    }

    private function attemptFor(
        string $username,
        Entry $entry,
    ): ?PasswordBindAttempt {
        $policy = $this->resolver->resolveFor($entry);
        if ($policy === null) {
            return null;
        }

        return new PasswordBindAttempt(
            name: $username,
            dn: $entry->getDn(),
            state: UserPasswordState::fromEntry($entry),
            policy: $policy,
        );
    }
}
