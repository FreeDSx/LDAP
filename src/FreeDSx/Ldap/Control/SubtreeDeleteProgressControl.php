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
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;

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

    /**
     * {@inheritDoc}
     *
     * @param AbstractType<mixed> $type
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $progress = parent::decodeEncodedValue($type);
        if (!$progress instanceof SequenceType) {
            throw new ProtocolException('The subtree delete progress control is malformed.');
        }
        $deleted = $progress->getChild(0);
        if (!$deleted instanceof IntegerType) {
            throw new ProtocolException('The subtree delete progress control is malformed.');
        }

        return parent::mergeControlData(
            new static(
                $deleted->getValue(),
                self::remainingIn($progress->getChild(1)),
            ),
            $type,
        );
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

    /**
     * @param AbstractType<mixed>|null $remaining
     *
     * @throws EncoderException
     */
    private static function remainingIn(?AbstractType $remaining): ?int
    {
        if ($remaining === null) {
            return null;
        }
        if (!$remaining instanceof IncompleteType || $remaining->getTagNumber() !== 0) {
            throw new ProtocolException('The subtree delete progress control is malformed.');
        }

        $value = (new LdapEncoder())->complete(
            $remaining,
            AbstractType::TAG_TYPE_INTEGER,
        )->getValue();

        return is_int($value)
            ? $value
            : null;
    }
}
