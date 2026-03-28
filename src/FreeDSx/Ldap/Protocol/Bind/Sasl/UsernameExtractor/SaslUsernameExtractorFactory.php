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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use FreeDSx\Sasl\Mechanism\ScramMechanism;

/**
 * Creates a single SaslUsernameExtractorInterface instance for the requested SASL mechanism.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslUsernameExtractorFactory
{
    /**
     * @throws RuntimeException if no extractor is registered for the given mechanism.
     */
    public function make(string $mechanism): SaslUsernameExtractorInterface
    {
        return match (true) {
            $mechanism === PlainMechanism::NAME
                => new PlainUsernameExtractor(),
            in_array($mechanism, ScramMechanism::VARIANTS, true)
                => new ScramUsernameExtractor(),
            $mechanism === CramMD5Mechanism::NAME,
            $mechanism === DigestMD5Mechanism::NAME
                => new UsernameFieldExtractor(),
            default => throw new RuntimeException(
                sprintf('No username extractor is registered for the SASL mechanism "%s".', $mechanism)
            ),
        };
    }
}
