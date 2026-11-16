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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl;

use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Sasl\SaslContext;

/**
 * Honors the authzid a completed SASL exchange carried, deciding which identity the bind acts as.
 *
 * @internal
 */
readonly class SaslAuthorizer
{
    public function __construct(private AuthzIdResolver $authzIdResolver) {}

    /**
     * Returns the token to bind as, which is the authenticated one unless the client asked to act as another.
     *
     * @throws OperationException when the authzid is malformed or may not be assumed.
     */
    public function authorize(
        SaslContext $context,
        BindToken $authenticated,
    ): AuthenticatedTokenInterface {
        $rawAuthzId = $this->requestedAuthzId(
            $context->getAuthzId(),
            $authenticated->getUsername(),
        );
        if ($rawAuthzId === null) {
            return $authenticated;
        }

        try {
            return $this->assume(
                $authenticated,
                $rawAuthzId,
            );
        } catch (OperationException $e) {
            // RFC 4513 5 refuses the bind with invalidCredentials when the authzid may not be assumed.
            throw new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
                $e,
            );
        }
    }

    /**
     * @throws OperationException when the authzid is malformed or may not be assumed.
     */
    private function assume(
        BindToken $authenticated,
        string $rawAuthzId,
    ): AuthenticatedTokenInterface {
        try {
            $authzId = AuthzId::fromString($rawAuthzId);
        } catch (InvalidArgumentException) {
            $this->authzIdResolver->deny(
                $authenticated,
                $rawAuthzId,
            );
        }

        $effective = $this->authzIdResolver->assume(
            $authenticated,
            $authzId,
        );
        // An assumption that leaves no bound identity is refused rather than ignored.
        if (!$effective instanceof AuthenticatedTokenInterface) {
            $this->authzIdResolver->deny(
                $authenticated,
                $rawAuthzId,
            );
        }

        return $effective;
    }

    /**
     * The authzid to honor, or null when it is absent or repeats the authentication identity as sent (common in PLAIN).
     */
    private function requestedAuthzId(
        ?string $rawAuthzId,
        ?string $authcId,
    ): ?string {
        if ($rawAuthzId === null || $rawAuthzId === '' || $rawAuthzId === $authcId) {
            return null;
        }

        return $rawAuthzId;
    }
}
