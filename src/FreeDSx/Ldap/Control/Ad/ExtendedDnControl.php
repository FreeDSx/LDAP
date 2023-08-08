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

namespace FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IntegerType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use function count;

/**
 * Used to represent the Extended DN control.
 *
 * @see https://msdn.microsoft.com/en-us/library/cc223349.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ExtendedDnControl extends Control
{
    public function __construct(
        private bool $useHexFormat = false,
        string $controlType = self::OID_EXTENDED_DN,
        bool $criticality = false,
    ) {
        parent::__construct(
            controlType: $controlType,
            criticality: $criticality,
        );
    }

    public function getUseHexFormat(): bool
    {
        return $this->useHexFormat;
    }

    public function setUseHexFormat(bool $useHexFormat): self
    {
        $this->useHexFormat = $useHexFormat;

        return $this;
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        if (!$type instanceof SequenceType) {
            throw new ProtocolException('The extended DN control is malformed.');
        }
        [0 => $oid, 1 => $criticality, 2 => $value] = self::parseAsn1ControlValues($type);

        $useHexFormat = false;
        if ($value !== null) {
            $request = self::decodeEncodedValue($type);
            if (!$request instanceof SequenceType) {
                throw new ProtocolException('An ExtendedDn control value must be a sequence type.');
            }
            $useHexFormat = $request->getChild(0);
            if (!$useHexFormat instanceof IntegerType) {
                throw new ProtocolException('An ExtendedDn control value sequence 0 must be an integer type.');
            }
            $useHexFormat = ($useHexFormat->getValue() === 0);
        }

        return new static(
            $useHexFormat,
            $oid,
            $criticality,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $useHexFormat = $this->useHexFormat ? 0 : 1;
        $this->controlValue = Asn1::sequence(Asn1::integer($useHexFormat));

        return parent::toAsn1();
    }

    /**
     * @throws ProtocolException
     */
    protected static function validate(AbstractType $type): void
    {
        if (!($type instanceof SequenceType && count($type) === 1)) {
            throw new ProtocolException('An ExtendedDn control value must be a sequence type with 1 child.');
        }
        if (!$type->getChild(0) instanceof IntegerType) {
            throw new ProtocolException('An ExtendedDn control value sequence 0 must be an integer type.');
        }
    }
}
