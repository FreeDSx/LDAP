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

namespace FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;

/**
 * A Server Side Sorting request control value. RFC 2891.
 *
 * SortKeyList ::= SEQUENCE OF SEQUENCE {
 *     attributeType   AttributeDescription,
 *     orderingRule    [0] MatchingRuleId OPTIONAL,
 *     reverseOrder    [1] BOOLEAN DEFAULT FALSE }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SortingControl extends Control
{
    /**
     * @var SortKey[]
     */
    private array $sortKeys;

    public function __construct(SortKey ...$sortKeys)
    {
        $this->sortKeys = $sortKeys;
        parent::__construct(self::OID_SORTING);
    }

    public function addSortKeys(SortKey ...$sortKeys): self
    {
        foreach ($sortKeys as $sortKey) {
            $this->sortKeys[] = $sortKey;
        }

        return $this;
    }

    public function setSortKeys(SortKey ...$sortKeys): self
    {
        $this->sortKeys = $sortKeys;

        return $this;
    }

    /**
     * @return SortKey[]
     */
    public function getSortKeys(): array
    {
        return $this->sortKeys;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequenceOf();

        foreach ($this->sortKeys as $sortKey) {
            $child = Asn1::sequence(Asn1::octetString($sortKey->getAttribute()));
            if ($sortKey->getOrderingRule() !== null) {
                $child->addChild(Asn1::context(
                    tagNumber: 0,
                    type: Asn1::octetString($sortKey->getOrderingRule()),
                ));
            }
            if ($sortKey->getUseReverseOrder()) {
                $child->addChild(Asn1::context(
                    tagNumber: 1,
                    type: Asn1::boolean(true),
                ));
            }
            $this->controlValue->addChild($child);
        }

        return parent::toAsn1();
    }
}
