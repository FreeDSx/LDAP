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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\Auth\ExternalCredentialMapperInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ChallengeOptionsInterface;
use FreeDSx\Sasl\Options\ExternalOptions;

/**
 * Builds the SASL EXTERNAL options: validate the verified client certificate and resolve its directory identity.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ExternalMechanismOptionsBuilder implements MechanismOptionsBuilderInterface
{
    private ?Dn $resolvedDn = null;

    private ?string $username = null;

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly ServerOptions $options,
        private readonly ExternalCredentialMapperInterface $mapper,
        private readonly AuthzIdResolver $authzIdResolver,
    ) {}

    public function buildOptions(
        ?string $received,
        MechanismName $mechanism,
    ): ChallengeOptionsInterface {
        return (new ExternalOptions())->setValidate(
            fn(?string $authzId): bool => $this->validate(),
        );
    }

    public function getResolvedDn(): ?Dn
    {
        return $this->resolvedDn;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    /**
     * Validates the channel and resolves the certificate's authentication identity. A client-supplied
     * authzId is honored later, uniformly, by the SASL exchange.
     *
     * @throws OperationException when the channel is unsuitable for EXTERNAL
     */
    private function validate(): bool
    {
        $this->assertSecureChannel();

        $certificate = $this->queue->peerCertificate();
        if ($certificate === null) {
            throw new OperationException(
                'No client certificate was provided for SASL EXTERNAL.',
                ResultCode::INAPPROPRIATE_AUTHENTICATION,
            );
        }

        $authcId = $this->mapper->map($certificate);
        if ($authcId === null) {
            return false;
        }

        $authcEntry = $this->authzIdResolver->resolve($authcId);
        if ($authcEntry === null) {
            return false;
        }

        $this->resolvedDn = $authcEntry->getDn();
        $this->username = $authcEntry->getDn()->toString();

        return true;
    }

    /**
     * @throws OperationException when the connection is not a verified-client-certificate TLS channel
     */
    private function assertSecureChannel(): void
    {
        // LDAPS connections are encrypted from accept (the StartTLS-only isEncrypted flag is not set for them).
        if (!$this->options->getNetworkConfig()->isUseSsl() && !$this->queue->isEncrypted()) {
            throw new OperationException(
                'SASL EXTERNAL requires a TLS-protected connection.',
                ResultCode::CONFIDENTIALITY_REQUIRED,
            );
        }

        if (!$this->options->getNetworkConfig()->isSslValidateCert()) {
            throw new OperationException(
                'SASL EXTERNAL requires client certificate validation to be enabled.',
                ResultCode::INAPPROPRIATE_AUTHENTICATION,
            );
        }
    }
}
