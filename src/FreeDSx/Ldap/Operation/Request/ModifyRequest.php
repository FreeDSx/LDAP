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
use FreeDSx\Asn1\Type\SetOfType;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;

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
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ModifyRequest implements RequestInterface, DnRequestInterface
{
    protected const APP_TAG = 6;

    /**
     * @var Change[]
     */
    private array $changes;

    private Dn $dn;

    public function __construct(
        Dn|string $dn,
        Change ...$changes,
    ) {
        $this->setDn($dn);
        $this->changes = $changes;
    }

    /**
     * @return Change[]
     */
    public function getChanges(): array
    {
        return $this->changes;
    }

    public function setChanges(Change ...$changes): self
    {
        $this->changes = $changes;

        return $this;
    }

    public function setDn(Dn|string $dn): static
    {
        $this->dn = $dn instanceof Dn
            ? $dn
            : new Dn($dn);

        return $this;
    }

    public function getDn(): Dn
    {
        return $this->dn;
    }

    public function toAsn1(): SequenceType
    {
        $changes = Asn1::sequenceOf();

        foreach ($this->changes as $change) {
            $changeSeq = Asn1::sequence(Asn1::enumerated($change->getType()));

            $values = [];
            foreach ($change->getAttribute()->getValues() as $value) {
                $values[] = Asn1::octetString($value);
            }

            $changeSeq->addChild(Asn1::sequence(
                Asn1::octetString($change->getAttribute()->getDescription()),
                SetOfType::fromChildren($values),
            ));

            $changes->addChild($changeSeq);
        }

        return Asn1::application(self::APP_TAG, Asn1::sequence(
            Asn1::octetString($this->dn->toString()),
            $changes,
        ));
    }
}
