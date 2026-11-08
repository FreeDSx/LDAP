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

namespace FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;

/**
 * An attribute-value comparison request. RFC 4511, 4.10.
 *
 * CompareRequest ::= [APPLICATION 14] SEQUENCE {
 *     entry           LDAPDN,
 *     ava             AttributeValueAssertion }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class CompareRequest implements RequestInterface, DnRequestInterface
{
    protected const APP_TAG = 14;

    private Dn $dn;

    public function __construct(
        Dn|string $dn,
        private EqualityFilter $filter,
    ) {
        $this->setDn($dn);
    }

    public function getDn(): Dn
    {
        return $this->dn;
    }

    public function setDn(Dn|string $dn): static
    {
        $this->dn = $dn instanceof Dn
            ? $dn
            : new Dn($dn);

        return $this;
    }

    public function getFilter(): EqualityFilter
    {
        return $this->filter;
    }

    public function setFilter(EqualityFilter $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        return Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::octetString($this->dn->toString()),
            Asn1::universal(AbstractType::TAG_TYPE_SEQUENCE, $this->filter->toAsn1()),
        ));
    }
}
