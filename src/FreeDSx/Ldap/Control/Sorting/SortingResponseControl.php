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

namespace FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * A Server Side Sorting response control value. RFC 2891.
 *
 * SortResult ::= SEQUENCE {
 *     sortResult  ENUMERATED {
 *         success                   (0), -- results are sorted
 *         operationsError           (1), -- server internal failure
 *         timeLimitExceeded         (3), -- timelimit reached before
 *         -- sorting was completed
 *         strongAuthRequired        (8), -- refused to return sorted
 *                                        -- results via insecure
 *                                        -- protocol
 *         adminLimitExceeded       (11), -- too many matching entries
 *                                        -- for the server to sort
 *         noSuchAttribute          (16), -- unrecognized attribute
 *                                        -- type in sort key
 *         inappropriateMatching    (18), -- unrecognized or
 *                                        -- inappropriate matching
 *                                        -- rule in sort key
 *         insufficientAccessRights (50), -- refused to return sorted
 *                                        -- results to this client
 *         busy                     (51), -- too busy to process
 *         unwillingToPerform       (53), -- unable to sort
 *         other                    (80)
 *         },
 *     attributeType [0] AttributeDescription OPTIONAL }
 *
 *  @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SortingResponseControl extends Control
{
    public function __construct(
        private readonly int $result,
        private readonly ?string $attribute = null
    ) {
        parent::__construct(self::OID_SORTING_RESPONSE);
    }

    public function getResult(): int
    {
        return $this->result;
    }

    public function getAttribute(): ?string
    {
        return $this->attribute;
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $sorting = parent::decodeEncodedValue($type);
        if (!$sorting instanceof SequenceType) {
            throw new ProtocolException('The server side sorting response is malformed.');
        }
        $result = $sorting->getChild(0);
        $attribute = $sorting->getChild(1);
        if (!$result instanceof EnumeratedType) {
            throw new ProtocolException('The server side sorting response is malformed.');
        }

        $response = new static(
            $result->getValue(),
            ($attribute !== null) ? $attribute->getValue() : null
        );

        return parent::mergeControlData(
            $response,
            $type
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(Asn1::enumerated($this->result));
        if ($this->attribute !== null) {
            $this->controlValue->addChild(Asn1::context(
                tagNumber: 0,
                type: Asn1::octetString($this->attribute)
            ));
        }

        return parent::toAsn1();
    }
}
