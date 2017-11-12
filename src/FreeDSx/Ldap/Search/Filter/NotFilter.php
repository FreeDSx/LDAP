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
use FreeDSx\Ldap\Asn1\Encoder\BerEncoder;
use FreeDSx\Ldap\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Factory\FilterFactory;

/**
 * Represents the negation of a filter. RFC 4511, 4.5.1
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class NotFilter implements FilterInterface
{
    protected const CHOICE_TAG = 2;

    /**
     * @var FilterInterface
     */
    protected $filter;

    /**
     * @param FilterInterface $filter
     */
    public function __construct(FilterInterface $filter)
    {
        $this->filter = $filter;
    }

    /**
     * @return FilterInterface
     */
    public function get() : FilterInterface
    {
        return $this->filter;
    }

    /**
     * @param FilterInterface $filter
     * @return $this
     */
    public function set(FilterInterface $filter)
    {
        $this->filter = $filter;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1() : AbstractType
    {
        return Asn1::context(self::CHOICE_TAG, Asn1::sequence($this->filter->toAsn1()));
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $type = $type instanceof IncompleteType ? (new BerEncoder())->complete($type, AbstractType::TAG_TYPE_SEQUENCE) : $type;
        if (!($type instanceof SequenceType && count($type) === 1)) {
            throw new ProtocolException('The not filter is malformed');
        }

        return new self(FilterFactory::get($type->getChild(0)));
    }
}