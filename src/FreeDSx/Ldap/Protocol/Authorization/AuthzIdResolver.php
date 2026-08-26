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

namespace FreeDSx\Ldap\Protocol\Authorization;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Resolves an authorization identity to an entry, and authorizes an identity to assume one (RFC 4370 grant).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AuthzIdResolver
{
    public function __construct(
        private AccessControlInterface $accessControl,
        private ReadBackendInterface $backend,
        private BindNameResolverInterface $identityResolver,
        private EventLogger $eventLogger,
    ) {}

    /**
     * Resolve an authzId to its directory entry, or null when anonymous, malformed, or with no match.
     */
    public function resolve(AuthzId $authzId): ?Entry
    {
        try {
            return match (true) {
                $authzId->isType(AuthzIdType::Dn) => $this->backend->get(new Dn($authzId->getValue())),
                $authzId->isType(AuthzIdType::Username) => $this->identityResolver->resolve(
                    $authzId->getValue(),
                    $this->backend,
                ),
                default => null,
            };
        } catch (OperationException|UnexpectedValueException|InvalidArgumentException) {
            return null;
        }
    }

    /**
     * Authorize the authenticated identity to act as the requested authzId, returning the effective token.
     *
     * @throws OperationException when the assumption is not permitted
     */
    public function assume(
        AuthenticatedTokenInterface $token,
        AuthzId $authzId,
    ): TokenInterface {
        if ($authzId->isType(AuthzIdType::Anonymous)) {
            return $this->assumeAnonymous(
                $token,
                $authzId,
            );
        }

        // Authorizing as the already-authenticated identity needs no proxy grant (RFC 4513 section 3.2).
        if ($this->isAuthenticatedIdentity($authzId, $token)) {
            return $token;
        }

        // Acting as any other identity is a proxy request and requires the grant (checked before resolving).
        if (!$this->accessControl->mayUseControl($token, Control::OID_PROXY_AUTHORIZATION)) {
            $this->deny(
                $token,
                $authzId->toString(),
            );
        }
        $entry = $this->resolve($authzId);
        if ($entry === null) {
            $this->deny(
                $token,
                $authzId->toString(),
            );
        }
        $proxiedDn = $entry->getDn();
        $this->authorize(
            $token,
            $proxiedDn,
            $authzId,
        );

        return BindToken::fromSasl(
            username: $proxiedDn->toString(),
            resolvedDn: $proxiedDn,
            version: $token->getVersion(),
            authorizingDn: $token->getResolvedDn(),
        );
    }

    /**
     * Record the denial (with the attempted authzId for audit) and throw a generic denial to the client.
     *
     * @throws OperationException
     */
    public function deny(
        TokenInterface $token,
        string $authzId,
    ): never {
        $exception = new OperationException(
            'Proxied authorization denied.',
            ResultCode::AUTHORIZATION_DENIED,
        );
        $this->eventLogger->recordFailure(
            ServerEvent::ProxyAuthorizationDenied,
            $exception,
            [
                EventContext::CONTROL_OIDS => [Control::OID_PROXY_AUTHORIZATION],
                EventContext::AUTHZ_ID => $authzId,
            ],
            subject: $token,
        );

        throw $exception;
    }

    /**
     * Assume the anonymous identity (an empty authzId), which still requires the proxy-auth grant.
     *
     * @throws OperationException when the assumption is not permitted
     */
    private function assumeAnonymous(
        AuthenticatedTokenInterface $token,
        AuthzId $authzId,
    ): TokenInterface {
        if (!$this->accessControl->mayUseControl($token, Control::OID_PROXY_AUTHORIZATION)) {
            $this->deny(
                $token,
                $authzId->toString(),
            );
        }
        $this->authorize(
            $token,
            new Dn(''),
            $authzId,
        );

        return new AnonToken(
            null,
            $token->getVersion(),
            $token->getResolvedDn(),
        );
    }

    /**
     * Whether the authzId already names the authenticated identity, so no proxy assumption is involved.
     */
    private function isAuthenticatedIdentity(
        AuthzId $authzId,
        AuthenticatedTokenInterface $token,
    ): bool {
        if ($authzId->isType(AuthzIdType::Username)) {
            return $authzId->getValue() === $token->getUsername();
        }

        return $authzId->isType(AuthzIdType::Dn)
            && $this->isSameDn($authzId->getValue(), $token->getResolvedDn());
    }

    private function isSameDn(
        string $candidate,
        Dn $resolvedDn,
    ): bool {
        try {
            $normalized = (new Dn($candidate))->normalize()->toString();
        } catch (InvalidArgumentException|UnexpectedValueException) {
            return false;
        }

        return $normalized === $resolvedDn->normalize()->toString();
    }

    /**
     * @throws OperationException
     */
    private function authorize(
        AuthenticatedTokenInterface $token,
        Dn $proxiedDn,
        AuthzId $authzId,
    ): void {
        try {
            $this->accessControl->authorizeControl(
                $token,
                $proxiedDn,
                Control::OID_PROXY_AUTHORIZATION,
            );
        } catch (OperationException) {
            $this->deny(
                $token,
                $authzId->toString(),
            );
        }
    }
}
