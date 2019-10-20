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
    /**
     * @var int
     */
    protected $minimum;

    /**
     * @var int
     */
    protected $maximum;

    /**
     * @param int $min
     * @param int $max
     */
    public function __construct(int $min, int $max)
    {
        $this->minimum = $min;
        $this->maximum = $max;
        parent::__construct(self::OID_EXPECTED_ENTRY_COUNT, true);
    }

    /**
     * @return int
     */
    public function getMaximum(): int
    {
        return $this->maximum;
    }

    /**
     * @param int $max
     * @return $this
     */
    public function setMaximum(int $max)
    {
        $this->maximum = $max;

        return $this;
    }

    /**
     * @return int
     */
    public function getMinimum(): int
    {
        return $this->minimum;
    }

    /**
     * @param int $min
     * @return $this
     */
    public function setMinimum(int $min)
    {
        $this->minimum = $min;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
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
        $control = new self(
            $min->getValue(),
            $max->getValue()
        );

        return self::mergeControlData($control, $type);
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
     * @param AbstractType $type
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
