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
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Ldap\Entry\Dn;

/**
 * RFC 4511, 4.8
 *
 * DelRequest ::= [APPLICATION 10] LDAPDN
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DeleteRequest implements RequestInterface, DnRequestInterface
{
    protected const APP_TAG = 10;

    private Dn $dn;

    public function __construct(Dn|string $dn)
    {
        $this->setDn($dn);
    }

    public function setDn(Dn|string $dn): static
    {
        $this->dn = $dn instanceof Dn ? $dn : new Dn($dn);

        return $this;
    }

    public function getDn(): Dn
    {
        return $this->dn;
    }

    public function toAsn1(): OctetStringType
    {
        return Asn1::application(self::APP_TAG, Asn1::octetString($this->dn->toString()));
    }
}
