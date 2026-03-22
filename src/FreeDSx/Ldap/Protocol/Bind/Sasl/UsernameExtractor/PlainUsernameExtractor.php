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

use FreeDSx\Sasl\Encoder\PlainEncoder;
use FreeDSx\Sasl\Mechanism\PlainMechanism;
use FreeDSx\Sasl\SaslContext;

/**
 * Extracts the username from PLAIN SASL credential bytes (the authcid field).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PlainUsernameExtractor implements SaslUsernameExtractorInterface
{
    use UsernameExtractionTrait;

    /**
     * {@inheritDoc}
     */
    public function extractUsername(
        string $mechanism,
        string $credentials
    ): string {
        $message = (new PlainEncoder())->decode($credentials, new SaslContext());

        return $this->requireUsername($message, 'authcid', $mechanism);
    }

    public function supports(string $mechanism): bool
    {
        return $mechanism === PlainMechanism::NAME;
    }
}
