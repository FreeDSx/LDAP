<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Search\Filter;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Asn1\Type\AbstractType;

/**
 * Represents an extensible matching rule filter. RFC 4511, 4.5.1.7.7
 *
 * MatchingRuleAssertion ::= SEQUENCE {
 *     matchingRule    [1] MatchingRuleId OPTIONAL,
 *     type            [2] AttributeDescription OPTIONAL,
 *     matchValue      [3] AssertionValue,
 *     dnAttributes    [4] BOOLEAN DEFAULT FALSE }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MatchingRuleFilter implements FilterInterface
{
    protected const CHOICE_TAG = 9;

    /**
     * @var null|string
     */
    protected $matchingRule;

    /**
     * @var null|string
     */
    protected $attribute;

    /**
     * @var string
     */
    protected $value;

    /**
     * @var bool
     */
    protected $useDnAttributes;

    /**
     * @param null|string $matchingRule
     * @param null|string $attribute
     * @param string $value
     * @param bool $useDnAttributes
     */
    public function __construct(?string $matchingRule, ?string $attribute, string $value, bool $useDnAttributes = false)
    {
        $this->matchingRule = $matchingRule;
        $this->attribute = $attribute;
        $this->value = $value;
        $this->useDnAttributes = $useDnAttributes;
    }

    /**
     * @return null|string
     */
    public function getAttribute() : ?string
    {
        return $this->attribute;
    }

    /**
     * @param null|string $attribute
     * @return $this
     */
    public function setAttribute(?string $attribute)
    {
        $this->attribute = $attribute;

        return $this;
    }

    /**
     * @return null|string
     */
    public function getMatchingRule() : ?string
    {
        return $this->matchingRule;
    }

    /**
     * @param null|string $matchingRule
     * @return $this
     */
    public function setMatchingRule(?string $matchingRule)
    {
        $this->matchingRule = $matchingRule;

        return $this;
    }

    /**
     * @return string
     */
    public function getValue() : string
    {
        return $this->value;
    }

    /**
     * @param string $value
     * @return $this
     */
    public function setValue(string $value)
    {
        $this->value = $value;

        return $this;
    }

    /**
     * @return bool
     */
    public function getUseDnAttributes() : bool
    {
        return $this->useDnAttributes;
    }

    /**
     * @param bool $useDnAttributes
     * @return $this
     */
    public function setUseDnAttributes(bool $useDnAttributes)
    {
        $this->useDnAttributes = $useDnAttributes;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        //@todo implement me...
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        /** @var \FreeDSx\Ldap\Asn1\Type\SequenceType $matchingRule */
        $matchingRule = Asn1::context(self::CHOICE_TAG, Asn1::sequence());

        if ($this->matchingRule !== null) {
            $matchingRule->addChild(Asn1::context(1, Asn1::ldapString($this->matchingRule)));
        }
        if ($this->attribute !== null) {
            $matchingRule->addChild(Asn1::context(2, Asn1::ldapString($this->attribute)));
        }
        $matchingRule->addChild(Asn1::context(3, Asn1::octetString($this->value)));
        $matchingRule->addChild(Asn1::context(4, Asn1::boolean($this->useDnAttributes)));

        return $matchingRule;
    }
}
