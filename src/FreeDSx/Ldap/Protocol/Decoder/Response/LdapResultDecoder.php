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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;

/**
 * Decodes a response that holds only an LDAPResult, such as a search done or a modify response.
 *
 * @template T of LdapResult
 * @implements OperationDecoderInterface<T>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class LdapResultDecoder implements OperationDecoderInterface
{
    /**
     * @param class-string<T> $resultClass the response to build.
     */
    public function __construct(private string $resultClass) {}

    /**
     * @param AbstractType<mixed> $type
     * @return T
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): LdapResult {
        $fields = LdapResultFields::of(
            $type,
            $context,
        );

        return new $this->resultClass(
            $fields->resultCode,
            $fields->dn,
            $fields->diagnosticMessage,
            ...$fields->referrals,
        );
    }
}
