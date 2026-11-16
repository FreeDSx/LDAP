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
use FreeDSx\Ldap\Exception\AnswerableExceptionInterface;
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
 *
 * @internal
 */
readonly class SaslBindPolicyEnforcer
{
    public function __construct(
        private BindNameResolverInterface $nameResolver,
        private ReadBackendInterface $backend,
        private PasswordPolicyResolver $resolver,
        private PasswordPolicyBindGuard $guard,
        private PasswordPolicyContext $context,
    ) {}

    /**
     * Records a failed exchange, refusing a locked account first as a simple bind does.
     *
     * @throws AnswerableExceptionInterface
     */
    public function recordFailure(?string $username): void
    {
        if ($username === null) {
            return;
        }

        $entry = $this->nameResolver->resolve(
            $username,
            $this->backend,
        );

        if ($entry === null) {
            // Otherwise a name that exists is measurably slower to refuse than one that does not.
            $this->guard->delayUnknownIdentity($this->resolver->resolveDefault());

            return;
        }
        $attempt = $this->attemptFor(
            $username,
            $entry,
        );

        if ($attempt === null) {
            return;
        }

        $this->guard->preBind($attempt);
        $this->guard->recordFailure($attempt);
    }

    /**
     * Refuses a locked account that completed an exchange, returning the attempt to record once the bind succeeds.
     *
     * @throws OperationException when the account is locked.
     */
    public function preBind(
        string $username,
        Dn $resolvedDn,
    ): ?PasswordBindAttempt {
        $entry = $this->backend->get($resolvedDn);
        if ($entry === null) {
            return null;
        }
        $attempt = $this->attemptFor(
            $username,
            $entry,
        );
        if ($attempt === null) {
            return null;
        }

        $this->guard->preBind($attempt);

        return $attempt;
    }

    /**
     * @throws OperationException when the password is expired without grace.
     */
    public function recordSuccess(PasswordBindAttempt $attempt): void
    {
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
            uuid: $entry->getUuidOrFail(),
            state: UserPasswordState::fromEntry($entry),
            policy: $policy,
        );
    }
}
