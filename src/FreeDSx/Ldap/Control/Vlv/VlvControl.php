<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Control\Vlv;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;

/**
 * Represents a VLV Request. draft-ietf-ldapext-ldapv3-vlv-09
 *
 * VirtualListViewRequest ::= SEQUENCE {
 *     beforeCount    INTEGER (0..maxInt),
 *     afterCount     INTEGER (0..maxInt),
 *     target       CHOICE {
 *         byOffset        [0] SEQUENCE {
 *             offset          INTEGER (1 .. maxInt),
 *             contentCount    INTEGER (0 .. maxInt) },
 *         greaterThanOrEqual [1] AssertionValue },
 *     contextID     OCTET STRING OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class VlvControl extends Control
{
    use VlvTrait;

    private int $after;

    private int $before;

    private ?GreaterThanOrEqualFilter $filter;

    public function __construct(
        int $before,
        int $after,
        ?int $offset = null,
        ?int $count = null,
        GreaterThanOrEqualFilter $filter = null,
        ?string $contextId = null
    ) {
        $this->before = $before;
        $this->after = $after;
        $this->offset = $offset;
        $this->count = $count;
        $this->filter = $filter;
        $this->contextId = $contextId;
        parent::__construct(self::OID_VLV);
    }

    public function getAfter(): int
    {
        return $this->after;
    }

    public function setAfter(int $after): self
    {
        $this->after = $after;

        return $this;
    }

    public function getBefore(): int
    {
        return $this->before;
    }

    public function setBefore(int $before): self
    {
        $this->before = $before;

        return $this;
    }

    public function setCount(?int $count): self
    {
        $this->count = $count;

        return $this;
    }

    public function setContextId(?string $contextId): self
    {
        $this->contextId = $contextId;

        return $this;
    }

    public function setOffset(?int $offset): self
    {
        $this->offset = $offset;

        return $this;
    }

    public function getFilter(): ?GreaterThanOrEqualFilter
    {
        return $this->filter;
    }

    public function setFilter(GreaterThanOrEqualFilter $filter = null): self
    {
        $this->filter = $filter;

        return $this;
    }

    /**
     * @throws EncoderException
     * @throws RuntimeException
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer($this->before),
            Asn1::integer($this->after)
        );
        if ($this->filter === null && ($this->count === null || $this->offset === null)) {
            throw new RuntimeException('You must specify a filter or offset and count for a VLV request.');
        }
        if ($this->filter !== null) {
            $this->controlValue->addChild(Asn1::context(1, $this->filter->toAsn1()));
        } else {
            $this->controlValue->addChild(Asn1::context(0, Asn1::sequence(
                Asn1::integer((int) $this->offset),
                Asn1::integer((int) $this->count)
            )));
        }

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     */
    public static function fromAsn1(AbstractType $type): static
    {
        throw new RuntimeException('Control parsing not yet implemented.');
    }
}
