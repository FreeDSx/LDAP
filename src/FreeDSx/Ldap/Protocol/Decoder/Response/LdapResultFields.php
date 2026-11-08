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

namespace FreeDSx\Ldap\Protocol\Decoder\Response;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UrlParseException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\FieldValueTrait;

use function array_slice;

/**
 * The result code, matched DN, diagnostic message and referrals of a received LDAPResult (RFC 4511 4.1.9).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class LdapResultFields
{
    use FieldValueTrait;

    private const MALFORMED = 'The LDAP result is malformed.';

    private const MALFORMED_RESULT_CODE = 'The LDAP result code is malformed.';

    /**
     * @param list<LdapUrl> $referrals
     */
    public function __construct(
        public int $resultCode,
        public string $dn,
        public string $diagnosticMessage,
        public array $referrals,
    ) {}

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     * @throws EncoderException
     */
    public static function of(
        AbstractType $type,
        DecodeContext $context,
    ): self {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException(self::MALFORMED);
        }
        $referrals = self::referralsOf(
            $type,
            $context,
        );
        $resultCode = $type->getChild(0);
        if (!$resultCode instanceof EnumeratedType) {
            throw new ProtocolException(self::MALFORMED);
        }
        $dn = self::stringOf(
            $type->getChild(1),
            self::MALFORMED,
        );
        $diagnosticMessage = self::stringOf(
            $type->getChild(2),
            self::MALFORMED,
        );

        return new self(
            self::enumeratedOf(
                $resultCode,
                self::MALFORMED_RESULT_CODE,
            ),
            $dn,
            $diagnosticMessage,
            $referrals,
        );
    }

    public function result(): LdapResult
    {
        return new LdapResult(
            $this->resultCode,
            $this->dn,
            $this->diagnosticMessage,
            ...$this->referrals,
        );
    }

    /**
     * @return list<LdapUrl>
     * @throws ProtocolException
     * @throws EncoderException
     */
    private static function referralsOf(
        SequenceType $type,
        DecodeContext $context,
    ): array {
        $referrals = [];

        foreach (array_slice($type->getChildren(), 3) as $child) {
            if ($child->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC || $child->getTagNumber() !== 3) {
                continue;
            }
            if (!$child instanceof IncompleteType) {
                throw new ProtocolException('The ASN1 structure for the referrals is malformed.');
            }

            $urls = self::urlsIn($context->complete(
                $child,
                AbstractType::TAG_TYPE_SEQUENCE,
            ));
            // Appended in place for performance.
            foreach ($urls as $url) {
                $referrals[] = $url;
            }
            // The field is only sent when it holds a URI.
            if ($referrals === []) {
                throw new ProtocolException('The LDAP result holds no usable referral URI.');
            }
        }

        return $referrals;
    }

    /**
     * @param AbstractType<mixed> $referrals
     * @return list<LdapUrl>
     * @throws ProtocolException
     */
    private static function urlsIn(AbstractType $referrals): array
    {
        $urls = [];
        foreach ($referrals->getChildren() as $ldapUrl) {
            $url = self::stringOf(
                $ldapUrl,
                'The ASN1 structure for a referral is malformed.',
            );

            try {
                $urls[] = LdapUrl::parse($url);
            } catch (UrlParseException) {
                // RFC 4511 4.1.10 makes the URIs alternatives to one another.
            }
        }

        return $urls;
    }
}
