<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Operation\Request;

use PhpDs\Ldap\Asn1\Asn1;
use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Entry\Change;
use PhpDs\Ldap\Entry\Dn;

/**
 * A Modify Request. RFC 4511, 4.6
 *
 * ModifyRequest ::= [APPLICATION 6] SEQUENCE {
 *     object          LDAPDN,
 *     changes         SEQUENCE OF change SEQUENCE {
 *         operation       ENUMERATED {
 *             add     (0),
 *             delete  (1),
 *             replace (2),
 *             ...  },
 *         modification    PartialAttribute } }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ModifyRequest implements RequestInterface
{
    protected const APP_TAG = 6;

    /**
     * @var Change[]
     */
    protected $changes;

    /**
     * @var Dn
     */
    protected $dn;

    /**
     * @param string $dn
     * @param Change[] ...$changes
     */
    public function __construct($dn, Change ...$changes)
    {
        $this->setDn($dn);
        $this->changes = $changes;
    }

    /**
     * @return Change[]
     */
    public function getChanges() : array
    {
        return $this->changes;
    }

    /**
     * @param Change[] ...$changes
     * @return $this
     */
    public function setChanges(Change ...$changes)
    {
        $this->changes = $changes;

        return $this;
    }

    /**
     * @param string|Dn $dn
     * @return $this
     */
    public function setDn($dn)
    {
        $this->dn = $dn instanceof $dn ? $dn : new Dn($dn);

        return $this;
    }

    /**
     * @return Dn
     */
    public function getDn() : Dn
    {
        return $this->dn;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        // TODO: Implement fromAsn1() method.
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $changes = Asn1::sequenceOf();

        foreach ($this->changes as $change) {
            $changeSeq = Asn1::sequence(Asn1::enumerated($change->getType()));

            $changeSeq->addChild(Asn1::sequence(
                Asn1::octetString($change->getAttribute()->getName()),
                Asn1::setOf(...array_map(function ($value) {
                    return Asn1::octetString($value);
                }, $change->getAttribute()->getValues()))
            ));

            $changes->addChild($changeSeq);
        }

        return Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::ldapDn($this->dn->toString()),
            $changes
        ));
    }
}
