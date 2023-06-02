<?php

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
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\BooleanType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
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
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class MatchingRuleFilter implements FilterInterface, Stringable
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
        bool $useDnAttributes = false
    ) {
        $this->matchingRule = $matchingRule;
        $this->attribute = $attribute;
        $this->value = $value;
        $this->useDnAttributes = $useDnAttributes;
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

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        /** @var SequenceType $matchingRule */
        $matchingRule = Asn1::context(
            tagNumber: self::CHOICE_TAG,
            type: Asn1::sequence()
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
        $matchingRule->addChild(Asn1::context(
            tagNumber: 4,
            type: Asn1::boolean($this->useDnAttributes),
        ));

        return $matchingRule;
    }

    /**
     * {@inheritdoc}
     */
    public function toString(): string
    {
        $filter = '';
        if ($this->attribute !== null) {
            $filter = $this->attribute;
        }
        if ($this->matchingRule !== null) {
            $filter .= ':' . $this->matchingRule;
        }
        if ($this->useDnAttributes) {
            $filter .= ':dn';
        }

        return self::PAREN_LEFT
            . $filter
            . self::FILTER_EXT
            . Attribute::escape($this->value)
            . self::PAREN_RIGHT;
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     */
    public static function fromAsn1(AbstractType $type): self
    {
        $type = $type instanceof IncompleteType ? (new LdapEncoder())->complete($type, AbstractType::TAG_TYPE_SEQUENCE) : $type;
        if (!($type instanceof SequenceType && (count($type) >= 1 && count($type) <= 4))) {
            throw new ProtocolException('The matching rule filter is malformed');
        }
        $matchingRule = null;
        $matchingType = null;
        $matchValue = null;
        $useDnAttr = null;

        foreach ($type->getChildren() as $child) {
            if ($child->getTagClass() !== AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
                continue;
            }
            if ($child->getTagNumber() === 1) {
                $matchingRule = $child;
            } elseif ($child->getTagNumber() === 2) {
                $matchingType = $child;
            } elseif ($child->getTagNumber() === 3) {
                $matchValue = $child;
            } elseif ($child->getTagNumber() === 4) {
                $useDnAttr = $child;
            }
        }
        if (!$matchValue instanceof OctetStringType) {
            throw new ProtocolException('The matching rule filter is malformed.');
        }
        if ($matchingRule !== null && !$matchingRule instanceof OctetStringType) {
            throw new ProtocolException('The matching rule filter is malformed.');
        }
        if ($matchingType !== null && !$matchingType instanceof OctetStringType) {
            throw new ProtocolException('The matching rule filter is malformed.');
        }
        if ($useDnAttr !== null && !$useDnAttr instanceof BooleanType) {
            throw new ProtocolException('The matching rule filter is malformed.');
        }
        $matchingRule = ($matchingRule !== null) ? $matchingRule->getValue() : null;
        $matchingType = ($matchingType !== null) ? $matchingType->getValue() : null;
        $useDnAttr = $useDnAttr !== null && $useDnAttr->getValue();

        return new self(
            $matchingRule,
            $matchingType,
            $matchValue->getValue(),
            $useDnAttr
        );
    }
}
