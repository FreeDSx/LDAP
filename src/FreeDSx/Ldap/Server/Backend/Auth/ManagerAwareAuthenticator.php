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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\ManagerToken;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;
use Throwable;

/**
 * Recognizes the configured manager super-user at bind time, ahead of the backend and password policy.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ManagerAwareAuthenticator implements PasswordAuthenticatableInterface
{
    public function __construct(
        private PasswordAuthenticatableInterface $inner,
        private ManagerIdentity $manager,
        private PasswordHashService $hashService,
    ) {}

    /**
     * @throws OperationException
     */
    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        if (!$this->isManager($name)) {
            return $this->inner->authenticate(
                $name,
                $password,
            );
        }

        // The manager DN is owned by the config identity: a wrong password fails outright, never falling through
        // to a colliding directory entry, and never touching password-policy lockout.
        if (!$this->hashService->verify($password, $this->manager->hashedPassword(), $this->manager->dn())) {
            throw new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            );
        }

        return new ManagerToken($this->manager->dn());
    }

    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        return $this->inner->getSaslIdentity(
            $username,
            $mechanism,
        );
    }

    private function isManager(string $name): bool
    {
        try {
            return $this->manager->matches(new Dn($name));
        } catch (Throwable) {
            return false;
        }
    }
}
