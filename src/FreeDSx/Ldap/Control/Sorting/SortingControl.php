<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\Control;

/**
 * A Server Side Sorting request control value. RFC 2891.
 *
 * SortKeyList ::= SEQUENCE OF SEQUENCE {
 *     attributeType   AttributeDescription,
 *     orderingRule    [0] MatchingRuleId OPTIONAL,
 *     reverseOrder    [1] BOOLEAN DEFAULT FALSE }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SortingControl extends Control
{
    /**
     * @var SortKey[]
     */
    protected $sortKeys = [];

    /**
     * @param SortKey[] ...$sortKeys
     */
    public function __construct(SortKey ...$sortKeys)
    {
        $this->sortKeys = $sortKeys;
        parent::__construct(self::OID_SORTING);
    }

    /**
     * @param SortKey[] ...$sortKeys
     * @return $this
     */
    public function addSortKeys(SortKey ...$sortKeys)
    {
        foreach ($sortKeys as $sortKey) {
            $this->sortKeys[] = $sortKey;
        }

        return $this;
    }

    /**
     * @param SortKey[] ...$sortKeys
     * @return $this
     */
    public function setSortKeys(SortKey ...$sortKeys)
    {
        $this->sortKeys = $sortKeys;

        return $this;
    }

    /**
     * @return SortKey[]
     */
    public function getSortKeys() : array
    {
        return $this->sortKeys;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        // TODO: Implement fromAsn1() method.
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequenceOf();

        foreach ($this->sortKeys as $sortKey) {
            $child = Asn1::sequence(Asn1::ldapString($sortKey->getAttribute()));
            if ($sortKey->getOrderingRule() !== null) {
                $child->addChild(Asn1::context(0, Asn1::ldapString($sortKey->getOrderingRule())));
            }
            if ($sortKey->getUseReverseOrder()) {
                $child->addChild(Asn1::context(1, Asn1::boolean(true)));
            }
            $this->controlValue->addChild($child);
        }

        return parent::toAsn1();
    }
}
