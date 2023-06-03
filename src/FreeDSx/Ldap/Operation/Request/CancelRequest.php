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
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * RFC 3909. A request to cancel an operation.
 *
 * cancelRequestValue ::= SEQUENCE {
 *     cancelID        MessageID
 *     -- MessageID is as defined in [RFC2251]
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class CancelRequest extends ExtendedRequest
{
    private int $messageId;

    public function __construct(int $messageId)
    {
        $this->messageId = $messageId;
        parent::__construct(self::OID_CANCEL);
    }

    public function getMessageId(): int
    {
        return $this->messageId;
    }

    public function setMessageId(int $messageId): self
    {
        $this->messageId = $messageId;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->requestValue = Asn1::sequence(Asn1::integer($this->messageId));

        return parent::toAsn1();
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $value = self::decodeEncodedValue($type);
        if (!($value instanceof SequenceType && $value->getChild(0) instanceof IntegerType)) {
            throw new ProtocolException('The cancel request value is malformed.');
        }

        return new static($value->getChild(0)->getValue());
    }
}
