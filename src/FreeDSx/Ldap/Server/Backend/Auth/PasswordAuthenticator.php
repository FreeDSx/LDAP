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
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

/**
 * Resolves the bind name to an Entry and verifies its userPassword; supports {SHA}, {SSHA}, {MD5}, {SMD5}, and plaintext.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PasswordAuthenticator implements PasswordAuthenticatableInterface
{
    public function __construct(
        private readonly BindNameResolverInterface $resolver,
        private readonly LdapBackendInterface $backend,
        private readonly PasswordHashService $hashService = new PasswordHashService(),
    ) {}

    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        $entry = $this->resolver->resolve(
            $name,
            $this->backend,
        );

        if ($entry === null) {
            $this->denyCredentials();
        }

        $attr = $entry->get('userPassword');

        if ($attr === null) {
            $this->denyCredentials();
        }

        foreach ($attr->getValues() as $stored) {
            if ($this->hashService->verify($password, $stored)) {
                return new BindToken(
                    AuthzId::fromDn($entry->getDn()),
                    $name,
                );
            }
        }

        $this->denyCredentials();
    }

    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        $entry = $this->resolver->resolve(
            $username,
            $this->backend,
        );

        if ($entry === null) {
            return null;
        }

        $password = $entry->get('userPassword')?->getValues()[0];

        if ($password === null) {
            return null;
        }

        // Only PLAIN verifies the presented password against the stored value. Every other mechanism keys on
        // it directly, so a stored hash would stand in as the shared secret and authenticate whoever holds it.
        if ($mechanism !== MechanismName::PLAIN && $this->hashService->isHashed($password)) {
            return null;
        }

        return new SaslIdentity(
            $password,
            $entry->getDn(),
        );
    }

    private function denyCredentials(): never
    {
        throw new OperationException(
            'Invalid credentials.',
            ResultCode::INVALID_CREDENTIALS,
        );
    }
}
