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
use FreeDSx\Ldap\Exception\RuntimeException;
use Stringable;

/**
 * Represents a substring filter. RFC 4511, 4.5.1.7.2.
 *
 * SubstringFilter ::= SEQUENCE {
 *     type           AttributeDescription,
 *     substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
 *         initial [0] AssertionValue,  -- can occur at most once
 *         any     [1] AssertionValue,
 *         final   [2] AssertionValue } -- can occur at most once
 *     }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SubstringFilter implements FilterInterface, FilterAttributeInterface, Stringable
{
    use FilterAttributeTrait;

    protected const CHOICE_TAG = 4;

    private ?string $startsWith;

    private ?string $endsWith;

    /**
     * @var string[]
     */
    private array $contains;

    public function __construct(
        string $attribute,
        ?string $startsWith = null,
        ?string $endsWith = null,
        string ...$contains,
    ) {
        $this->attribute = $attribute;
        $this->startsWith = $startsWith;
        $this->endsWith = $endsWith;
        $this->contains = $contains;
    }

    /**
     * Get the value that it should start with.
     */
    public function getStartsWith(): ?string
    {
        return $this->startsWith;
    }

    /**
     * Set the value it should start with.
     */
    public function setStartsWith(?string $value): self
    {
        $this->startsWith = $value;

        return $this;
    }

    /**
     * Get the value it should end with.
     */
    public function getEndsWith(): ?string
    {
        return $this->endsWith;
    }

    /**
     * Set the value it should end with.
     */
    public function setEndsWith(?string $value): self
    {
        $this->endsWith = $value;

        return $this;
    }

    /**
     * Get the values it should contain.
     *
     * @return string[]
     */
    public function getContains(): array
    {
        return $this->contains;
    }

    /**
     * Set the values it should contain.
     */
    public function setContains(string ...$values): self
    {
        $this->contains = $values;

        return $this;
    }

    /**
     * @throws RuntimeException
     */
    public function toAsn1(): SequenceType
    {
        if ($this->startsWith === null && $this->endsWith === null && count($this->contains) === 0) {
            throw new RuntimeException('You must provide a contains, starts with, or ends with value to the substring filter.');
        }
        $substrings = Asn1::sequenceOf();

        if ($this->startsWith !== null) {
            $substrings->addChild(Asn1::context(
                tagNumber: 0,
                type: Asn1::octetString($this->startsWith),
            ));
        }

        foreach ($this->contains as $contain) {
            $substrings->addChild(Asn1::context(
                tagNumber: 1,
                type: Asn1::octetString($contain),
            ));
        }

        if ($this->endsWith !== null) {
            $substrings->addChild(Asn1::context(
                tagNumber: 2,
                type: Asn1::octetString($this->endsWith),
            ));
        }

        return Asn1::context(
            tagNumber: self::CHOICE_TAG,
            type: Asn1::sequence(
                Asn1::octetString($this->attribute),
                $substrings,
            ),
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toString(): string
    {
        $filter = self::PAREN_LEFT . $this->attributeToString() . self::FILTER_EQUAL;

        $value = '';
        if (count($this->contains) !== 0) {
            $value = array_map(function ($value) {
                return Attribute::escape($value);
            }, $this->contains);
            $value = '*' . implode('*', $value) . '*';
        }
        if ($this->startsWith !== null) {
            $startsWith = Attribute::escape($this->startsWith);
            $value = ($value === '' ? $startsWith . '*' : $startsWith) . $value;
        }
        if ($this->endsWith !== null) {
            $endsWith = Attribute::escape($this->endsWith);
            $value = $value . ($value === '' ? '*' . $endsWith : $endsWith);
        }

        return $filter . $value . self::PAREN_RIGHT;
    }
}
