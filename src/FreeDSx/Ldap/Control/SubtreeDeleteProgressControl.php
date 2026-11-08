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

namespace FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\SequenceType;

/**
 * How far a subtree delete got in one request, sent when it stops before the base and has to be resubmitted.
 *
 * SubtreeDeleteProgress ::= SEQUENCE {
 *     deleted       INTEGER (0 .. maxInt),
 *     remaining [0] INTEGER (0 .. maxInt) OPTIONAL }
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SubtreeDeleteProgressControl extends Control
{
    public function __construct(
        private readonly int $deleted,
        private readonly ?int $remaining = null,
    ) {
        parent::__construct(self::OID_SUBTREE_DELETE_PROGRESS);
    }

    /**
     * Entries the request removed.
     */
    public function getDeleted(): int
    {
        return $this->deleted;
    }

    /**
     * Entries still to remove, when the server knows without counting them.
     */
    public function getRemaining(): ?int
    {
        return $this->remaining;
    }

    public function toAsn1(): SequenceType
    {
        $this->controlValue = Asn1::sequence(Asn1::integer($this->deleted));
        if ($this->remaining !== null) {
            $this->controlValue->addChild(Asn1::context(
                tagNumber: 0,
                type: Asn1::integer($this->remaining),
            ));
        }

        return parent::toAsn1();
    }
}
