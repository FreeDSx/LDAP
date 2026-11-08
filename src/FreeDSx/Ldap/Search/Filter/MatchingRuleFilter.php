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

namespace FreeDSx\Ldap\Search\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\FilterParseException;
use Stringable;

/**
 * Represents an extensible matching rule filter. RFC 4511, 4.5.1.7.7
 *
 * MatchingRuleAssertion ::= SEQUENCE {
 *     matchingRule    [1] MatchingRuleId OPTIONAL,
 *     type            [2] AttributeDescription OPTIONAL,
 *     matchValue      [3] AssertionValue,
 *     dnAttributes    [4] BOOLEAN DEFAULT FALSE }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MatchingRuleFilter implements FilterInterface, FilterAttributeInterface, Stringable
{
    protected const CHOICE_TAG = 9;

    private ?string $matchingRule;

    private ?string $attribute;

    private string $value;

    private bool $useDnAttributes;

    public function __construct(
        ?string $matchingRule,
        ?string $attribute,
        string $value,
        bool $useDnAttributes = false,
    ) {
        $this->matchingRule = $matchingRule;
        $this->attribute = $attribute;
        $this->value = $value;
        $this->useDnAttributes = $useDnAttributes;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    public function getAttribute(): ?string
    {
        return $this->attribute;
    }

    public function setAttribute(?string $attribute): self
    {
        $this->attribute = $attribute;

        return $this;
    }

    public function getMatchingRule(): ?string
    {
        return $this->matchingRule;
    }

    public function setMatchingRule(?string $matchingRule): self
    {
        $this->matchingRule = $matchingRule;

        return $this;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function setValue(string $value): self
    {
        $this->value = $value;

        return $this;
    }

    public function getUseDnAttributes(): bool
    {
        return $this->useDnAttributes;
    }

    public function setUseDnAttributes(bool $useDnAttributes): self
    {
        $this->useDnAttributes = $useDnAttributes;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        $matchingRule = Asn1::context(
            tagNumber: self::CHOICE_TAG,
            type: Asn1::sequence(),
        );

        if ($this->matchingRule !== null) {
            $matchingRule->addChild(Asn1::context(
                tagNumber: 1,
                type: Asn1::octetString($this->matchingRule),
            ));
        }
        if ($this->attribute !== null) {
            $matchingRule->addChild(Asn1::context(
                tagNumber: 2,
                type: Asn1::octetString($this->attribute),
            ));
        }
        $matchingRule->addChild(Asn1::context(
            tagNumber: 3,
            type: Asn1::octetString($this->value),
        ));
        // RFC 4511 5.1: a field holding its default value is absent from the encoding.
        if ($this->useDnAttributes) {
            $matchingRule->addChild(Asn1::context(
                tagNumber: 4,
                type: Asn1::boolean(true),
            ));
        }

        return $matchingRule;
    }

    /**
     * {@inheritdoc}
     */
    public function toString(): string
    {
        // RFC 4515 3: attr [":dn"] [":" matchingrule] ":=" value.
        $filter = $this->attributeToString();
        if ($this->useDnAttributes) {
            $filter .= ':dn';
        }
        if ($this->matchingRule !== null) {
            $filter .= ':' . $this->matchingRule;
        }

        return self::PAREN_LEFT
            . $filter
            . self::FILTER_EXT
            . Attribute::escape($this->value)
            . self::PAREN_RIGHT;
    }

    /**
     * The attribute as a filter string names it, empty when the assertion carries none.
     *
     * @throws FilterParseException
     */
    private function attributeToString(): string
    {
        if ($this->attribute === null) {
            return '';
        }

        if (!Attribute::isValidDescription($this->attribute)) {
            throw new FilterParseException(sprintf(
                'The attribute "%s" has no valid filter string representation.',
                $this->attribute,
            ));
        }

        return $this->attribute;
    }
}
