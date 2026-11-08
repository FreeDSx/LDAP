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

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\FieldValueTrait;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;

use function count;
use function is_int;

/**
 * Decodes an extensible match filter (RFC 4511 4.5.1.7.7).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class MatchingRuleFilterDecoder implements FilterShapeDecoderInterface
{
    use FieldValueTrait;

    private const MALFORMED = 'The matching rule filter is malformed.';

    private const CHILD_TAG_MAP = [
        AbstractType::TAG_CLASS_CONTEXT_SPECIFIC => [
            1 => AbstractType::TAG_TYPE_OCTET_STRING,
            2 => AbstractType::TAG_TYPE_OCTET_STRING,
            3 => AbstractType::TAG_TYPE_OCTET_STRING,
            4 => AbstractType::TAG_TYPE_BOOLEAN,
        ],
    ];

    public function decode(
        AbstractType $type,
        FilterDecodeRun $run,
    ): MatchingRuleFilter {
        // The children are context tagged primitives whose universal types must be supplied to decode them.
        if ($type instanceof IncompleteType) {
            $type = $run->context->complete(
                $type,
                AbstractType::TAG_TYPE_SEQUENCE,
                self::CHILD_TAG_MAP,
            );
        }
        if (!($type instanceof SequenceType && count($type) >= 1)) {
            throw new ProtocolException('The matching rule filter is malformed');
        }

        $fields = $this->fieldsOf($type);
        $value = self::stringOf(
            $fields[3] ?? null,
            self::MALFORMED,
        );

        return new MatchingRuleFilter(
            $this->optionalStringOf($fields[1] ?? null),
            $this->optionalStringOf($fields[2] ?? null),
            $value,
            $this->dnAttributesOf($fields[4] ?? null),
        );
    }

    /**
     * Keeps the last of each context tagged field, keyed by its tag.
     *
     * @return array<int, AbstractType<mixed>>
     */
    private function fieldsOf(SequenceType $type): array
    {
        $fields = [];
        foreach ($type->getChildren() as $child) {
            $tagNumber = $child->getTagNumber();
            if (
                $child->getTagClass() === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC
                && is_int($tagNumber)
                && $tagNumber >= 1
                && $tagNumber <= 4
            ) {
                $fields[$tagNumber] = $child;
            }
        }

        return $fields;
    }

    /**
     * @param AbstractType<mixed>|null $field
     * @throws ProtocolException
     */
    private function optionalStringOf(?AbstractType $field): ?string
    {
        return $field === null
            ? null
            : self::stringOf(
                $field,
                self::MALFORMED,
            );
    }

    /**
     * @param AbstractType<mixed>|null $field
     * @throws ProtocolException
     */
    private function dnAttributesOf(?AbstractType $field): bool
    {
        if ($field !== null && !$field instanceof BooleanType) {
            throw new ProtocolException(self::MALFORMED);
        }

        return $field !== null
            && $field->getValue();
    }
}
