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

namespace FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdType;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

/**
 * Binds the per-connection upstream client and represents that identity for the proxied session.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProxyAuthenticator implements PasswordAuthenticatableInterface
{
    /**
     * @param bool $asksUpstreamIdentity whether a bind asks the upstream which identity it bound as
     */
    public function __construct(
        private ProxyUpstreamSession $session,
        private bool $asksUpstreamIdentity = false,
    ) {}

    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        try {
            $this->session->bind(
                $name,
                $password,
            );
            $identity = $this->asksUpstreamIdentity
                ? $this->session->whoAmI()
                : null;
        } catch (BindException $e) {
            throw new OperationException(
                $e->getMessage(),
                $e->getCode(),
            );
        } catch (ConnectionException) {
            throw new OperationException(
                'The upstream LDAP server is unavailable.',
                ResultCode::UNAVAILABLE,
            );
        }

        return $this->tokenFor(
            $name,
            $identity,
        );
    }

    /**
     * SASL bind is not proxied; returns null so SASL mechanisms reject.
     */
    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        return null;
    }

    /**
     * The identity the upstream reports when it names one, otherwise the name as it was bound.
     */
    private function tokenFor(
        string $name,
        ?string $identity,
    ): BindToken {
        $authzId = $this->namedIdentity($identity);

        if ($authzId === null) {
            return BindToken::fromDn($name);
        }

        return new BindToken(
            $authzId,
            $name,
        );
    }

    /**
     * The reported identity, or null when it is empty or malformed.
     */
    private function namedIdentity(?string $identity): ?AuthzId
    {
        if ($identity === null) {
            return null;
        }

        try {
            $authzId = AuthzId::fromString($identity);
        } catch (InvalidArgumentException) {
            return null;
        }

        if ($authzId->getValue() === '') {
            return null;
        }
        if ($authzId->isType(AuthzIdType::Dn) && !Dn::isValid($authzId->getValue())) {
            return null;
        }

        return $authzId;
    }
}
