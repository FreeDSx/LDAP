<?php

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
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a paged results control request value. RFC 2696.
 *
 * realSearchControlValue ::= SEQUENCE {
 *     size            INTEGER (0..maxInt),
 *                          -- requested page size from client
 *                          -- result set size estimate from server
 *     cookie          OCTET STRING }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PagingControl extends Control
{
    private string $cookie;

    private int $size;

    public function __construct(
        int $size,
        string $cookie = ''
    ) {
        $this->size = $size;
        $this->cookie = $cookie;
        parent::__construct(self::OID_PAGING);
    }

    public function getCookie(): string
    {
        return $this->cookie;
    }

    public function getSize(): int
    {
        return $this->size;
    }

    public function setCookie(string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }

    public function setSize(int $size): self
    {
        $this->size = $size;

        return $this;
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $paging = self::decodeEncodedValue($type);
        if (!$paging instanceof SequenceType) {
            throw new ProtocolException('A paged control value must be a sequence type with 2 children.');
        }
        $count = $paging->getChild(0);
        $cookie = $paging->getChild(1);
        if (!$count instanceof IntegerType) {
            throw new ProtocolException('A paged control value sequence 0 must be an integer type.');
        }
        if (!$cookie instanceof OctetStringType) {
            throw new ProtocolException('A paged control value sequence 1 must be an octet string type.');
        }
        $control = new static(
            $count->getValue(),
            $cookie->getValue()
        );

        return self::mergeControlData(
            $control,
            $type
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer($this->size),
            Asn1::octetString($this->cookie)
        );

        return parent::toAsn1();
    }
}
