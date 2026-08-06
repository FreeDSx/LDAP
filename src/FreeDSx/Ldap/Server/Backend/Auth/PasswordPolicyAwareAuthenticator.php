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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyBindGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

/**
 * Decorates an authenticator to enforce draft-behera password policy on the simple-bind path.
 */
final readonly class PasswordPolicyAwareAuthenticator implements PasswordAuthenticatableInterface
{
    public function __construct(
        private PasswordAuthenticatableInterface $decoratedAuthenticator,
        private BindNameResolverInterface $nameResolver,
        private LdapBackendInterface $backend,
        private PasswordPolicyResolver $policyResolver,
        private PasswordPolicyBindGuard $guard,
    ) {}

    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        $entry = $this->nameResolver->resolve(
            $name,
            $this->backend,
        );
        if ($entry === null) {
            try {
                return $this->decoratedAuthenticator->authenticate(
                    $name,
                    $password,
                );
            } catch (OperationException $cause) {
                if ($cause->getCode() === ResultCode::INVALID_CREDENTIALS) {
                    // Otherwise a name that exists is measurably slower to refuse than one that does not.
                    $this->guard->delayUnknownIdentity($this->policyResolver->resolveDefault());
                }

                throw $cause;
            }
        }

        $policy = $this->policyResolver->resolveFor($entry);
        if ($policy === null) {
            return $this->decoratedAuthenticator->authenticate(
                $name,
                $password,
            );
        }

        $attempt = new PasswordBindAttempt(
            name: $name,
            dn: $entry->getDn(),
            state: UserPasswordState::fromEntry($entry),
            policy: $policy,
        );
        $this->guard->preBind($attempt);

        try {
            $token = $this->decoratedAuthenticator->authenticate(
                $name,
                $password,
            );
        } catch (OperationException $cause) {
            if ($cause->getCode() === ResultCode::INVALID_CREDENTIALS) {
                $this->guard->recordFailure($attempt);
            }

            throw $cause;
        }

        $this->guard->recordSuccess($attempt);

        if ($attempt->state->mustChange) {
            $token->markMustChangePassword();
        }

        return $token;
    }

    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        return $this->decoratedAuthenticator->getSaslIdentity(
            $username,
            $mechanism,
        );
    }
}
