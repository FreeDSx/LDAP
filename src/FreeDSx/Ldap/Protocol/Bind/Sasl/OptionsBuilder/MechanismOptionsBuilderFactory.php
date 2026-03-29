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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\UsernameFieldExtractor;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\GenericBackend;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use FreeDSx\Sasl\Mechanism\ScramMechanism;

/**
 * Creates a single MechanismOptionsBuilderInterface instance for the requested SASL mechanism.
 *
 * Challenge-based mechanisms (CRAM-MD5, DIGEST-MD5, SCRAM) require the backend to implement
 * SaslHandlerInterface. An OperationException is thrown if the requirement is not met, so
 * the client receives a well-formed LDAP error response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MechanismOptionsBuilderFactory
{
    public function __construct(
        private readonly LdapBackendInterface $backend = new GenericBackend(),
    ) {
    }

    /**
     * @throws OperationException if the mechanism is unsupported or requires SaslHandlerInterface.
     */
    public function make(
        string $mechanism,
        PasswordAuthenticatableInterface $authenticator,
    ): MechanismOptionsBuilderInterface {
        return match (true) {
            $mechanism === PlainMechanism::NAME
                => new PlainMechanismOptionsBuilder($authenticator),
            $mechanism === CramMD5Mechanism::NAME && $this->backend instanceof SaslHandlerInterface
                => new CramMD5MechanismOptionsBuilder($this->backend),
            $mechanism === DigestMD5Mechanism::NAME && $this->backend instanceof SaslHandlerInterface
                => new DigestMD5MechanismOptionsBuilder($this->backend, new UsernameFieldExtractor()),
            in_array($mechanism, ScramMechanism::VARIANTS, true) && $this->backend instanceof SaslHandlerInterface
                => new ScramMechanismOptionsBuilder($this->backend),
            default => throw new OperationException(
                sprintf(
                    'The SASL mechanism "%s" requires the request handler to implement %s.',
                    $mechanism,
                    SaslHandlerInterface::class,
                ),
                ResultCode::OTHER,
            ),
        };
    }
}
