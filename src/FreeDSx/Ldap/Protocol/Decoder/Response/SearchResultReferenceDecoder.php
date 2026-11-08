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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\UrlParseException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\FieldValueTrait;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;

/**
 * Decodes a search result reference (RFC 4511 4.5.3) and the URIs it continues the search at.
 *
 * @implements OperationDecoderInterface<SearchResultReference>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SearchResultReferenceDecoder implements OperationDecoderInterface
{
    use FieldValueTrait;

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): SearchResultReference {
        $referrals = [];
        foreach ($type->getChildren() as $referral) {
            $url = self::stringOf(
                $referral,
                'The search result reference is malformed.',
            );
            try {
                $referrals[] = LdapUrl::parse($url);
            } catch (UrlParseException) {
                // RFC 4511 4.1.10 makes the URIs alternatives, so an unusable one is ignored.
            }
        }

        if ($referrals === []) {
            throw new ProtocolException('The search result reference holds no usable URI.');
        }

        return new SearchResultReference(...$referrals);
    }
}
