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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\UsernameFieldExtractor;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
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
    /**
     * @throws RuntimeException if no builder is registered for the given mechanism.
     */
    public function make(
        string $mechanism,
        RequestHandlerInterface $dispatcher,
    ): MechanismOptionsBuilderInterface {
        return match (true) {
            $mechanism === PlainMechanism::NAME
                => new PlainMechanismOptionsBuilder($dispatcher),
            $mechanism === CramMD5Mechanism::NAME && $dispatcher instanceof SaslHandlerInterface
                => new CramMD5MechanismOptionsBuilder($dispatcher),
            $mechanism === DigestMD5Mechanism::NAME && $dispatcher instanceof SaslHandlerInterface
                => new DigestMD5MechanismOptionsBuilder($dispatcher, new UsernameFieldExtractor()),
            in_array($mechanism, ScramMechanism::VARIANTS, true) && $dispatcher instanceof SaslHandlerInterface
                => new ScramMechanismOptionsBuilder($dispatcher),
            default => throw new RuntimeException(
                sprintf('No options builder is registered for the SASL mechanism "%s".', $mechanism)
            ),
        };
    }
}
