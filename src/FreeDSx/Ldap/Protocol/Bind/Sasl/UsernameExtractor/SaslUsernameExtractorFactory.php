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
use FreeDSx\Sasl\Mechanism\MechanismName;

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
    public function make(MechanismName $mechanism): SaslUsernameExtractorInterface
    {
        return match (true) {
            $mechanism === MechanismName::PLAIN
                => new PlainUsernameExtractor(),
            $mechanism->isScram()
                => new ScramUsernameExtractor(),
            $mechanism === MechanismName::CRAM_MD5
                => new UsernameFieldExtractor(),
            default => throw new RuntimeException(
                sprintf('No username extractor is registered for the SASL mechanism "%s".', $mechanism->value),
            ),
        };
    }
}
