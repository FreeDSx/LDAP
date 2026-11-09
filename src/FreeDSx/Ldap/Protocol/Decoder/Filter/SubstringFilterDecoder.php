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
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\FieldValueTrait;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;

use function count;
use function is_string;

/**
 * Decodes a substring filter (RFC 4511 4.5.1.7.2) and each part it matches.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SubstringFilterDecoder implements FilterShapeDecoderInterface
{
    use FieldValueTrait;

    private const MALFORMED = 'The substring filter is malformed.';

    public function decode(
        AbstractType $type,
        FilterDecodeRun $run,
    ): SubstringFilter {
        if ($type instanceof IncompleteType) {
            // The attribute and the sequence of parts are not items, while a trailing component counts as one.
            $type = $run->completeWithinItems(
                $type,
                AbstractType::TAG_TYPE_SEQUENCE,
                otherElements: 2,
            );
        }
        if (!($type instanceof SequenceType && count($type->getChildren()) >= 2)) {
            throw new ProtocolException('The substring type is malformed');
        }

        $attribute = self::stringOf(
            $type->getChild(0),
            self::MALFORMED,
        );
        $substrings = $type->getChild(1);
        if (!($substrings instanceof SequenceType && count($substrings) > 0)) {
            throw new ProtocolException(self::MALFORMED);
        }
        [$startsWith, $endsWith, $contains] = $this->substrings($substrings);

        return new SubstringFilter(
            $attribute,
            $startsWith,
            $endsWith,
            ...$contains,
        );
    }

    /**
     * @return array{0: ?string, 1: ?string, 2: list<string>}
     * @throws ProtocolException
     */
    private function substrings(SequenceType $substrings): array
    {
        $startsWith = null;
        $endsWith = null;
        $contains = [];

        foreach ($substrings->getChildren() as $substring) {
            if ($substring->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                throw new ProtocolException(self::MALFORMED);
            }
            // The initial and final parts can occur only once each, while any part can occur many times.
            $tagNumber = $substring->getTagNumber();
            if ($tagNumber === 0 && $startsWith === null) {
                $startsWith = $substring;
            } elseif ($tagNumber === 1) {
                $contains[] = $this->valueOf($substring) ?? '';
            } elseif ($tagNumber === 2 && $endsWith === null) {
                $endsWith = $substring;
            } else {
                throw new ProtocolException(self::MALFORMED);
            }
        }

        return [
            $this->valueOf($startsWith),
            $this->valueOf($endsWith),
            $contains,
        ];
    }

    /**
     * @param AbstractType<mixed>|null $part
     */
    private function valueOf(?AbstractType $part): ?string
    {
        $value = $part?->getValue();

        return is_string($value)
            ? $value
            : null;
    }
}
