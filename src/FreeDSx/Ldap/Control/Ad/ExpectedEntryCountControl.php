<?php

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

/**
 * Represents an Expected Entry Count control. Defined in MS-ADTS 3.1.1.3.4.1.33. The control value request definition is:
 *
 *  ExpectedEntryCountRequestValue ::= SEQUENCE {
 *      searchEntriesMin    INTEGER
 *      searchEntriesMax    INTEGER
 *  }
 *
 * @see https://msdn.microsoft.com/en-us/library/jj216720.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ExpectedEntryCountControl extends Control
{
    private int $minimum;

    private int $maximum;

    public function __construct(
        int $min,
        int $max
    ) {
        $this->minimum = $min;
        $this->maximum = $max;
        parent::__construct(
            self::OID_EXPECTED_ENTRY_COUNT,
            true
        );
    }

    public function getMaximum(): int
    {
        return $this->maximum;
    }

    public function setMaximum(int $max): self
    {
        $this->maximum = $max;

        return $this;
    }

    public function getMinimum(): int
    {
        return $this->minimum;
    }

    public function setMinimum(int $min): self
    {
        $this->minimum = $min;

        return $this;
    }

    /**
     * {@inheritDoc}
     * @throws EncoderException
     * @throws PartialPduException
     */
    public static function fromAsn1(AbstractType $type): static
    {
        $request = self::decodeEncodedValue($type);
        if (!$request instanceof SequenceType) {
            throw new ProtocolException('An ExpectedEntryCount control value must be a sequence type.');
        }
        $min = $request->getChild(0);
        $max = $request->getChild(1);
        if (!$min instanceof IntegerType) {
            throw new ProtocolException('An ExpectedEntryCount control value sequence 0 must be an integer type.');
        }
        if (!$max instanceof IntegerType) {
            throw new ProtocolException('An ExpectedEntryCount control value sequence 1 must be an integer type.');
        }
        $control = new static(
            $min->getValue(),
            $max->getValue(),
        );

        return self::mergeControlData(
            $control,
            $type,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer($this->minimum),
            Asn1::integer($this->maximum)
        );

        return parent::toAsn1();
    }

    /**
     * @throws ProtocolException
     */
    protected static function validate(AbstractType $type): void
    {
        if (!($type instanceof SequenceType && count($type) === 2)) {
            throw new ProtocolException('An ExpectedEntryCount control value must be a sequence type with 2 children.');
        }
        if (!$type->getChild(0) instanceof IntegerType) {
            throw new ProtocolException('An ExpectedEntryCount control value sequence 0 must be an integer type.');
        }
        if (!$type->getChild(1) instanceof IntegerType) {
            throw new ProtocolException('An ExpectedEntryCount control value sequence 1 must be an integer type.');
        }
    }
}
