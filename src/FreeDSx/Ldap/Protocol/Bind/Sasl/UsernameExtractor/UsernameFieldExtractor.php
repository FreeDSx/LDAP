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
use FreeDSx\Sasl\Encoder\DigestMD5Encoder;
use FreeDSx\Sasl\Encoder\EncoderInterface;
use FreeDSx\Sasl\Mechanism\CramMD5Mechanism;
use FreeDSx\Sasl\Mechanism\DigestMD5Mechanism;
use FreeDSx\Sasl\SaslContext;

/**
 * Extracts the username from SASL credential bytes for mechanisms whose client response
 * contains a 'username' field (e.g. CRAM-MD5, DIGEST-MD5).
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
     *                                                   Defaults to CRAM-MD5 and DIGEST-MD5.
     */
    public function __construct(array $encoders = [])
    {
        $this->encoders = $encoders ?: [
            CramMD5Mechanism::NAME => new CramMD5Encoder(),
            DigestMD5Mechanism::NAME => new DigestMD5Encoder(),
        ];
    }

    /**
     * {@inheritDoc}
     */
    public function extractUsername(
        string $mechanism,
        string $credentials
    ): string {
        $encoder = $this->encoders[$mechanism];

        // Always decode as server-side: we are parsing a client response, not a server challenge.
        // For DIGEST-MD5 this is required; for others it is harmless.
        $context = new SaslContext();
        $context->setIsServerMode(true);
        $message = $encoder->decode(
            $credentials,
            $context
        );

        return $this->requireUsername($message, 'username', $mechanism);
    }

    public function supports(string $mechanism): bool
    {
        return isset($this->encoders[$mechanism]);
    }
}
