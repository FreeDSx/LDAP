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

use Closure;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;

/**
 * Creates a single MechanismOptionsBuilderInterface instance for the requested SASL mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MechanismOptionsBuilderFactory
{
    /**
     * @param (Closure(): MechanismOptionsBuilderInterface)|null $externalBuilderFactory builds a fresh EXTERNAL builder
     */
    public function __construct(
        private PasswordAuthenticatableInterface $authenticator,
        private ?Closure $externalBuilderFactory = null,
    ) {}

    /**
     * @throws OperationException if the mechanism is unsupported.
     */
    public function make(MechanismName $mechanism): MechanismOptionsBuilderInterface
    {
        return match (true) {
            $mechanism === MechanismName::PLAIN
                => new PlainMechanismOptionsBuilder($this->authenticator),
            $mechanism === MechanismName::CRAM_MD5
                => new CramMD5MechanismOptionsBuilder($this->authenticator),
            $mechanism->isScram()
                => new ScramMechanismOptionsBuilder($this->authenticator),
            $mechanism === MechanismName::EXTERNAL && $this->externalBuilderFactory !== null
                => ($this->externalBuilderFactory)(),
            default => throw new OperationException(
                sprintf('The SASL mechanism "%s" is not supported.', $mechanism->value),
                ResultCode::OTHER,
            ),
        };
    }
}
