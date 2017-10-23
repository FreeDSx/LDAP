<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Search\Filter;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Exception\RuntimeException;

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
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SubstringFilter implements FilterInterface
{
    use FilterAttributeTrait;

    protected const CHOICE_TAG = 4;

    /**
     * @var null|string
     */
    protected $startsWith;

    /**
     * @var null|string
     */
    protected $endsWith;

    /**
     * @var string[]
     */
    protected $contains = [];

    /**
     * @param string $attribute
     * @param null|string $startsWith
     * @param null|string $endsWith
     * @param string[] ...$contains
     */
    public function __construct(string $attribute, ?string $startsWith = null, ?string $endsWith = null, string ...$contains)
    {
        $this->attribute = $attribute;
        $this->startsWith = $startsWith;
        $this->endsWith = $endsWith;
        $this->contains = $contains;
    }

    /**
     * Get the value that it should start with.
     *
     * @return null|string
     */
    public function getStartsWith() : ?string
    {
        return $this->startsWith;
    }

    /**
     * Set the value it should start with.
     *
     * @param null|string $value
     * @return $this
     */
    public function setStartsWith(?string $value)
    {
        $this->startsWith = $value;

        return $this;
    }

    /**
     * Get the value it should end with.
     *
     * @return null|string
     */
    public function getEndsWith() : ?string
    {
        return $this->endsWith;
    }

    /**
     * Set the value it should end with.
     *
     * @param null|string $value
     * @return $this
     */
    public function setEndsWith(?string $value)
    {
        $this->endsWith = $value;

        return $this;
    }

    /**
     * Get the values it should contain.
     *
     * @return string[]
     */
    public function getContains() : array
    {
        return $this->contains;
    }

    /**
     * Set the values it should contain.
     *
     * @param string[] ...$values
     * @return $this
     */
    public function setContains(string ...$values)
    {
        $this->contains = $values;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        if ($this->startsWith === null && $this->endsWith === null && empty($this->contains)) {
            throw new RuntimeException('You must provide a contains, starts with, or ends with value to the substring filter.');
        }
        $substrings = Asn1::sequenceOf();

        if ($this->startsWith !== null) {
            $substrings->addChild(Asn1::context(0, Asn1::octetString($this->startsWith)));
        }

        foreach ($this->contains as $contain) {
            $substrings->addChild(Asn1::context(1, Asn1::octetString($contain)));
        }

        if ($this->endsWith !== null) {
            $substrings->addChild(Asn1::context(2, Asn1::octetString($this->endsWith)));
        }

        return Asn1::context(self::CHOICE_TAG, Asn1::sequence(
           Asn1::ldapString($this->attribute),
           $substrings
        ));
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        //@todo implement me...
    }
}
