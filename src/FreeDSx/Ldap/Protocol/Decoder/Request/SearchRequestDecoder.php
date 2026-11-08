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
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Protocol\Decoder\OperationDecoderInterface;

use function count;
use function is_int;

/**
 * Decodes a search request (RFC 4511 4.5.1), leaving its fields' ranges to the handlers that act on them.
 *
 * @implements OperationDecoderInterface<SearchRequest>
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SearchRequestDecoder implements OperationDecoderInterface
{
    public function __construct(private FilterDecoder $filters) {}

    /**
     * @param AbstractType<mixed> $type
     * @throws ProtocolException
     */
    public function decode(
        AbstractType $type,
        DecodeContext $context,
    ): SearchRequest {
        if (!($type instanceof SequenceType && count($type) >= 8)) {
            throw new ProtocolException('The search request is malformed');
        }
        $baseDn = $type->getChild(0);
        $scope = $type->getChild(1);
        $deref = $type->getChild(2);
        $sizeLimit = $type->getChild(3);
        $timeLimit = $type->getChild(4);
        $typesOnly = $type->getChild(5);
        $attributes = $type->getChild(7);

        $filter = $type->getChild(6);
        if ($filter === null) {
            throw new ProtocolException('The search request is malformed.');
        }
        // Decoded before the other fields are checked, so a filter past a limit is answered by that limit.
        $filter = $this->filters->decode(
            $filter,
            $context,
        );

        if (
            !($baseDn instanceof OctetStringType
            && $scope instanceof EnumeratedType
            && $deref instanceof EnumeratedType
            && $sizeLimit instanceof IntegerType
            && $timeLimit instanceof IntegerType
            && $typesOnly instanceof BooleanType
            && $attributes instanceof SequenceType)
        ) {
            throw new ProtocolException('The search request is malformed');
        }
        $attrList = $this->attributes($attributes);

        $scopeValue = $scope->getValue();
        $derefValue = $deref->getValue();
        $sizeLimitValue = $sizeLimit->getValue();
        $timeLimitValue = $timeLimit->getValue();
        if (
            !is_int($scopeValue)
            || !is_int($derefValue)
            || !is_int($sizeLimitValue)
            || !is_int($timeLimitValue)
        ) {
            throw new ProtocolException('The search request contains a non-integer numeric field.');
        }

        $search = new SearchRequest(
            $filter,
            ...$attrList,
        );
        $search->setScope($scopeValue);
        $search->setBaseDn($baseDn->getValue());
        $search->setDereferenceAliases($derefValue);
        $search->setSizeLimit($sizeLimitValue);
        $search->setTimeLimit($timeLimitValue);
        $search->setAttributesOnly($typesOnly->getValue());

        return $search;
    }

    /**
     * @return list<Attribute>
     * @throws ProtocolException
     */
    private function attributes(SequenceType $attributes): array
    {
        $attrList = [];
        foreach ($attributes->getChildren() as $attribute) {
            if (!$attribute instanceof OctetStringType) {
                throw new ProtocolException('The search request is malformed.');
            }
            $attrList[] = new Attribute($attribute->getValue());
        }

        return $attrList;
    }
}
