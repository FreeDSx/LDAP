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

use FreeDSx\Sasl\Encoder\CramMD5Encoder;
use FreeDSx\Sasl\Encoder\EncoderInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\SaslContext;

/**
 * Extracts the username from SASL credential bytes for mechanisms whose client response
 * contains a 'username' field (e.g. CRAM-MD5).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class UsernameFieldExtractor implements SaslUsernameExtractorInterface
{
    use UsernameExtractionTrait;

    /**
     * @var array<string, EncoderInterface>
     */
    private array $encoders;

    /**
     * @param array<string, EncoderInterface> $encoders Map of mechanism name to its encoder.
     *                                                   Defaults to CRAM-MD5.
     */
    public function __construct(array $encoders = [])
    {
        $this->encoders = $encoders ?: [
            MechanismName::CRAM_MD5->value => new CramMD5Encoder(),
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function extractUsername(
        MechanismName $mechanism,
        string $credentials,
    ): string {
        $encoder = $this->encoders[$mechanism->value];

        // Always decode as server-side: we are parsing a client response, not a server challenge.
        $context = new SaslContext();
        $context->setIsServerMode(true);
        $message = $encoder->decode(
            $credentials,
            $context,
        );

        return $this->requireUsername($message, 'username', $mechanism->value);
    }
}
