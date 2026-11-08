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

namespace FreeDSx\Ldap\Protocol\Decoder\Request;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Filter\AttributeValueAssertionDecoder;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;

use function count;

/**
 * Decodes a compare request (RFC 4511 4.10).
 *
 * @implements OperationDecoderInterface<CompareRequest>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class CompareRequestDecoder implements OperationDecoderInterface
{
    /**
     * @param AttributeValueAssertionDecoder<EqualityFilter> $assertions
     */
    public function __construct(private AttributeValueAssertionDecoder $assertions) {}

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): CompareRequest {
        if (!($type instanceof SequenceType && count($type->getChildren()) >= 2)) {
            throw new ProtocolException('The compare request is malformed');
        }
        $dn = $type->getChild(0);
        $ava = $type->getChild(1);

        if (!$dn instanceof OctetStringType || $ava === null) {
            throw new ProtocolException('The compare request is malformed.');
        }

        return new CompareRequest(
            $dn->getValue(),
            $this->assertions->decodeAssertion(
                $ava,
                $context,
            ),
        );
    }
}
