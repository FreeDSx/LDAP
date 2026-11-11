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

namespace FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Exception\AdminLimitExceededException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;

use function count;
use function sprintf;

/**
 * Decodes a server side sorting request control (RFC 2891).
 *
 * @extends EncodedValueControlDecoder<SortingControl>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SortingControlDecoder extends EncodedValueControlDecoder
{
    /**
     * The most sort keys a received sorting control may hold.
     */
    public const MAX_KEYS = 100;

    protected function decodeValue(
        AbstractType $value,
        DecodeContext $context,
    ): SortingControl {
        if (!$value instanceof SequenceType) {
            throw new ProtocolException('The sorting control is malformed.');
        }
        // RFC 2891 lets a server restrict the keys, and the decoded list is held for the whole search.
        if (count($value) > self::MAX_KEYS) {
            throw new AdminLimitExceededException(sprintf(
                'The sorting control holds more than %d sort keys.',
                self::MAX_KEYS,
            ));
        }

        $sortKeys = [];
        foreach ($value->getChildren() as $sequence) {
            if (!$sequence instanceof SequenceType) {
                throw new ProtocolException('The sort key is malformed.');
            }
            $sortKeys[] = $this->sortKey(
                $sequence,
                $context,
            );
        }

        return new SortingControl(...$sortKeys);
    }

    /**
     * @throws ProtocolException
     * @throws EncoderException
     */
    private function sortKey(
        SequenceType $sequence,
        DecodeContext $context,
    ): SortKey {
        $attrName = '';
        $matchRule = null;
        $useReverseOrder = false;

        foreach ($sequence->getChildren() as $keyItem) {
            $tagClass = $keyItem->getTagClass();
            if ($keyItem instanceof OctetStringType && $tagClass === AbstractType::TAG_CLASS_UNIVERSAL) {
                $attrName = $keyItem->getValue();
            } elseif (
                $keyItem instanceof IncompleteType
                && $tagClass === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC
                && $keyItem->getTagNumber() === 0
            ) {
                $matchRule = $keyItem->getValue();
            } elseif ($tagClass === AbstractType::TAG_CLASS_CONTEXT_SPECIFIC && $keyItem->getTagNumber() === 1) {
                $useReverseOrder = $this->reverseOrder(
                    $keyItem,
                    $context,
                );
            } else {
                throw new ProtocolException('The sorting control contains unexpected data.');
            }
        }
        if ($attrName === '') {
            throw new ProtocolException('The sort key is missing an attribute description.');
        }

        return new SortKey(
            attribute: $attrName,
            useReverseOrder: $useReverseOrder,
            orderingRule: $matchRule,
        );
    }

    /**
     * @param AbstractType<mixed> $keyItem
     * @throws ProtocolException
     * @throws EncoderException
     */
    private function reverseOrder(
        AbstractType $keyItem,
        DecodeContext $context,
    ): bool {
        if (!$keyItem instanceof IncompleteType) {
            throw new ProtocolException('The sorting control is malformed.');
        }
        $reverseFlag = $context->complete(
            $keyItem,
            AbstractType::TAG_TYPE_BOOLEAN,
        );
        if (!$reverseFlag instanceof BooleanType) {
            throw new ProtocolException('The sorting control reverseOrder flag is malformed.');
        }

        return $reverseFlag->getValue();
    }
}
