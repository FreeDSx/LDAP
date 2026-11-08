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

namespace FreeDSx\Ldap\Protocol\Decoder\Filter;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\FieldValueTrait;
use FreeDSx\Ldap\Search\Filter\AttributeValueAssertionInterface;
use FreeDSx\Ldap\Search\Filter\FilterInterface;

use function count;

/**
 * Decodes an equality, ordering or approximate filter (RFC 4511 4.5.1.7), or the assertion a compare carries.
 *
 * @template T of AttributeValueAssertionInterface&FilterInterface
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AttributeValueAssertionDecoder implements FilterShapeDecoderInterface
{
    use FieldValueTrait;

    private const MALFORMED = 'The attribute value assertion is malformed.';

    /**
     * @param class-string<T> $filterClass the filter to build.
     */
    public function __construct(private string $filterClass) {}

    /**
     * @return T
     */
    public function decode(
        AbstractType $type,
        FilterDecodeRun $run,
    ): FilterInterface {
        return $this->decodeAssertion(
            $type,
            $run->context,
        );
    }

    /**
     * Decodes the assertion alone, which a compare request carries outside of any filter.
     *
     * @param AbstractType<mixed> $type
     * @return T
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decodeAssertion(
        AbstractType $type,
        DecodeContext $context,
    ): FilterInterface {
        if ($type instanceof IncompleteType) {
            $type = $context->complete(
                $type,
                AbstractType::TAG_TYPE_SEQUENCE,
            );
        }
        if (!($type instanceof SequenceType && count($type) >= 2)) {
            throw new ProtocolException(self::MALFORMED);
        }

        return new $this->filterClass(
            self::stringOf(
                $type->getChild(0),
                self::MALFORMED,
            ),
            self::stringOf(
                $type->getChild(1),
                self::MALFORMED,
            ),
        );
    }
}
