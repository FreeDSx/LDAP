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

namespace FreeDSx\Ldap\Control\Vlv;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;

/**
 * Represents a VLV Response. draft-ietf-ldapext-ldapv3-vlv-09
 *
 * VirtualListViewResponse ::= SEQUENCE {
 *     targetPosition    INTEGER (0 .. maxInt),
 *     contentCount     INTEGER (0 .. maxInt),
 *     virtualListViewResult ENUMERATED {
 *         success (0),
 *         operationsError (1),
 *         protocolError (3),
 *         unwillingToPerform (53),
 *         insufficientAccessRights (50),
 *         timeLimitExceeded (3),
 *         adminLimitExceeded (11),
 *         innapropriateMatching (18),
 *         sortControlMissing (60),
 *         offsetRangeError (61),
 *         other(80),
 *         ... },
 *     contextID     OCTET STRING OPTIONAL }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class VlvResponseControl extends Control
{
    use VlvTrait;

    public function __construct(
        int $offset,
        int $count,
        private readonly int $result,
        ?string $contextId = null,
    ) {
        $this->offset = $offset;
        $this->count = $count;
        $this->contextId = $contextId;
        parent::__construct(self::OID_VLV_RESPONSE);
    }

    public function getResult(): int
    {
        return $this->result;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer((int) $this->offset),
            Asn1::integer((int) $this->count),
            Asn1::enumerated($this->result),
        );
        if ($this->contextId !== null) {
            $this->controlValue->addChild(new OctetStringType($this->contextId));
        }

        return parent::toAsn1();
    }
}
