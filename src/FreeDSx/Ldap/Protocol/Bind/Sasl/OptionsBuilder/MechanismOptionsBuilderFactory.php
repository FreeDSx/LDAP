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
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use FreeDSx\Sasl\Mechanism\ScramMechanism;

/**
 * Creates a single MechanismOptionsBuilderInterface instance for the requested SASL mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MechanismOptionsBuilderFactory
{
    public function __construct(
        private readonly PasswordAuthenticatableInterface $authenticator,
    ) {
    }

    /**
     * @throws OperationException if the mechanism is unsupported.
     */
    public function make(string $mechanism): MechanismOptionsBuilderInterface
    {
        return match (true) {
            $mechanism === PlainMechanism::NAME
                => new PlainMechanismOptionsBuilder($this->authenticator),
            $mechanism === CramMD5Mechanism::NAME
                => new CramMD5MechanismOptionsBuilder($this->authenticator),
            $mechanism === DigestMD5Mechanism::NAME
                => new DigestMD5MechanismOptionsBuilder($this->authenticator, new UsernameFieldExtractor()),
            in_array($mechanism, ScramMechanism::VARIANTS, true)
                => new ScramMechanismOptionsBuilder($this->authenticator),
            default => throw new OperationException(
                sprintf('The SASL mechanism "%s" is not supported.', $mechanism),
                ResultCode::OTHER,
            ),
        };
    }
}
