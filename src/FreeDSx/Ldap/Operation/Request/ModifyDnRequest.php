<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation\Request;

use FreeDSx\Ldap\Asn1\Asn1;
use FreeDSx\Ldap\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Rdn;

/**
 * A Modify DN Request. RFC 4511, 4.9
 *
 * ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
 *     entry           LDAPDN,
 *     newrdn          RelativeLDAPDN,
 *     deleteoldrdn    BOOLEAN,
 *     newSuperior     [0] LDAPDN OPTIONAL }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ModifyDnRequest implements RequestInterface
{
    protected const APP_TAG = 12;

    /**
     * @var Dn
     */
    protected $dn;

    /**
     * @var Rdn
     */
    protected $newRdn;

    /**
     * @var bool
     */
    protected $deleteOldRdn;

    /**
     * @var null|Dn
     */
    protected $newParentDn;

    /**
     * @param string|Dn $dn
     * @param string|Rdn $newRdn
     * @param bool $deleteOldRdn
     * @param null|string|Dn $newParentDn
     */
    public function __construct($dn, $newRdn, bool $deleteOldRdn, $newParentDn = null)
    {
        $this->setDn($dn);
        $this->setNewRdn($newRdn);
        $this->setNewParentDn($newParentDn);
        $this->deleteOldRdn = $deleteOldRdn;
    }

    /**
     * @return Dn
     */
    public function getDn() : Dn
    {
        return $this->dn;
    }

    /**
     * @param string}Dn $dn
     * @return $this
     */
    public function setDn($dn)
    {
        $this->dn = $dn instanceof Dn ? $dn : new Dn($dn);

        return $this;
    }

    /**
     * @return Rdn
     */
    public function getNewRdn() : Rdn
    {
        return $this->newRdn;
    }

    /**
     * @param string|Rdn $newRdn
     * @return $this
     */
    public function setNewRdn($newRdn)
    {
        $this->newRdn = $newRdn instanceof Rdn ? $newRdn : Rdn::create($newRdn);

        return $this;
    }

    /**
     * @return bool
     */
    public function getDeleteOldRdn() : bool
    {
        return $this->deleteOldRdn;
    }

    /**
     * @param bool $deleteOldRdn
     * @return $this
     */
    public function setDeleteOldRdn(bool $deleteOldRdn)
    {
        $this->deleteOldRdn = $deleteOldRdn;

        return $this;
    }

    /**
     * @return null|Dn
     */
    public function getNewParentDn() : ?Dn
    {
        return $this->newParentDn;
    }

    /**
     * @param null|string|Dn $newParentDn
     * @return $this
     */
    public function setNewParentDn($newParentDn)
    {
        if ($newParentDn !== null) {
            $newParentDn = $newParentDn instanceof Dn ? $newParentDn : new Dn($newParentDn);
        }
        $this->newParentDn = $newParentDn;

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
    public function toAsn1(): AbstractType
    {
        /** @var \FreeDSx\Ldap\Asn1\Type\SequenceType $asn1 */
        $asn1 = Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::ldapDn($this->dn->toString()),
            // @todo Make a RDN type. Future validation purposes?
            Asn1::ldapString($this->newRdn->toString()),
            Asn1::boolean($this->deleteOldRdn)
        ));
        if ($this->newParentDn !== null) {
            $asn1->addChild(Asn1::context(0, Asn1::ldapDn($this->newParentDn->toString())));
        }

        return $asn1;
    }
}
