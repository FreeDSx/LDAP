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
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Rdn;
use Stringable;

/**
 * A Modify DN Request. RFC 4511, 4.9
 *
 * ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
 *     entry           LDAPDN,
 *     newrdn          RelativeLDAPDN,
 *     deleteoldrdn    BOOLEAN,
 *     newSuperior     [0] LDAPDN OPTIONAL }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ModifyDnRequest implements RequestInterface, DnRequestInterface
{
    protected const APP_TAG = 12;

    private Dn $dn;

    private Rdn $newRdn;

    private ?Dn $newParentDn;

    public function __construct(
        Dn|Stringable|string $dn,
        Rdn|Stringable|string $newRdn,
        private bool $deleteOldRdn,
        Dn|Stringable|string|null $newParentDn = null,
    ) {
        $this->setDn($dn);
        $this->setNewRdn($newRdn);
        $this->setNewParentDn($newParentDn);
    }

    public function getDn(): Dn
    {
        return $this->dn;
    }

    public function setDn(Dn|Stringable|string $dn): static
    {
        $this->dn = $dn instanceof Dn
            ? $dn
            : new Dn((string) $dn);

        return $this;
    }

    public function getNewRdn(): Rdn
    {
        return $this->newRdn;
    }

    public function setNewRdn(Rdn|Stringable|string $newRdn): self
    {
        $this->newRdn = $newRdn instanceof Rdn
            ? $newRdn
            : Rdn::create((string) $newRdn);

        return $this;
    }

    public function getDeleteOldRdn(): bool
    {
        return $this->deleteOldRdn;
    }

    public function setDeleteOldRdn(bool $deleteOldRdn): self
    {
        $this->deleteOldRdn = $deleteOldRdn;

        return $this;
    }

    public function getNewParentDn(): ?Dn
    {
        return $this->newParentDn;
    }

    public function setNewParentDn(Dn|Stringable|string|null $newParentDn): self
    {
        if ($newParentDn !== null) {
            $newParentDn = $newParentDn instanceof Dn
                ? $newParentDn
                : new Dn((string) $newParentDn);
        }
        $this->newParentDn = $newParentDn;

        return $this;
    }

    public function toAsn1(): SequenceType
    {
        /** @var SequenceType $asn1 */
        $asn1 = Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::octetString($this->dn->toString()),
            // @todo Make a RDN type. Future validation purposes?
            Asn1::octetString($this->newRdn->toString()),
            Asn1::boolean($this->deleteOldRdn),
        ));
        if ($this->newParentDn !== null) {
            $asn1->addChild(Asn1::context(
                tagNumber: 0,
                type: Asn1::octetString($this->newParentDn->toString()),
            ));
        }

        return $asn1;
    }
}
