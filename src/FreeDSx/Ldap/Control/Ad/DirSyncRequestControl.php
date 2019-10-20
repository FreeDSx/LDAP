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
use FreeDSx\Asn1\Type\OctetStringType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a DirSync Request. Defined in MS-ADTS 3.1.1.3.4.1.3. The control value request definition is:
 *
 *  DirSyncRequestValue ::= SEQUENCE {
 *      Flags       INTEGER
 *      MaxBytes    INTEGER
 *      Cookie      OCTET STRING
 *  }
 *
 * @see https://msdn.microsoft.com/en-us/library/cc223347.aspx
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DirSyncRequestControl extends Control
{
    /**
     * If this flag is present, the client can only view objects and attributes that are otherwise accessible to the client.
     * If this flag is not present, the server checks if the client has access rights to read the changes in the NC.
     */
    public const FLAG_OBJECT_SECURITY = 0x00000001;

    /**
     * The server returns parent objects before child objects.
     */
    public const FLAG_ANCESTORS_FIRST_ORDER = 0x00000800;

    /**
     * This flag can optionally be passed to the DC, but it has no effect.
     */
    public const FLAG_PUBLIC_DATA_ONLY = 0x00002000;

    /**
     * If this flag is not present, all of the values, up to a server-specified limit, in a multivalued attribute are
     * returned when any value changes. If this flag is present, only the changed values are returned, provided the
     * attribute is a forward link value.
     *
     * Note: This flag needs to be encoded as a negative, due to how AD interprets the flags value.
     */
    public const FLAG_INCREMENTAL_VALUES = -0x80000000;

    /**
     * @var int
     */
    protected $flags;

    /**
     * @var int
     */
    protected $maxBytes;

    /**
     * @var string
     */
    protected $cookie;

    /**
     * @param int $flags
     * @param int $maxBytes
     * @param string $cookie
     */
    public function __construct(int $flags = self::FLAG_INCREMENTAL_VALUES, string $cookie = '', int $maxBytes = 2147483647)
    {
        $this->flags = $flags;
        $this->maxBytes = $maxBytes;
        $this->cookie = $cookie;
        parent::__construct(self::OID_DIR_SYNC, true);
    }

    /**
     * @return int
     */
    public function getFlags(): int
    {
        return $this->flags;
    }

    /**
     * @param int $flags
     * @return $this
     */
    public function setFlags(int $flags)
    {
        $this->flags = $flags;

        return $this;
    }

    /**
     * @return int
     */
    public function getMaxBytes(): int
    {
        return $this->maxBytes;
    }

    /**
     * @param int $maxBytes
     * @return $this
     */
    public function setMaxBytes(int $maxBytes)
    {
        $this->maxBytes = $maxBytes;

        return $this;
    }

    /**
     * @return string
     */
    public function getCookie(): string
    {
        return $this->cookie;
    }

    /**
     * @param string $cookie
     * @return $this
     */
    public function setCookie(string $cookie)
    {
        $this->cookie = $cookie;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromAsn1(AbstractType $type)
    {
        $request = self::decodeEncodedValue($type);
        if (!$request instanceof SequenceType) {
            throw new ProtocolException('A DirSyncRequest control value must be a sequence type with 3 children.');
        }
        $flags = $request->getChild(0);
        $cookie = $request->getChild(2);
        $maxBytes = $request->getChild(1);
        if (!$flags instanceof IntegerType) {
            throw new ProtocolException('A DirSyncRequest control value sequence 0 must be an integer type.');
        }
        if (!$maxBytes instanceof IntegerType) {
            throw new ProtocolException('A DirSyncRequest control value sequence 1 must be an integer type.');
        }
        if (!$cookie instanceof OctetStringType) {
            throw new ProtocolException('A DirSyncRequest control value sequence 2 must be an octet string type.');
        }

        /** @var SequenceType $request */
        $control = new self(
            $flags->getValue(),
            $cookie->getValue(),
            $maxBytes->getValue()
        );

        return self::mergeControlData($control, $type);
    }

    /**
     * {@inheritdoc}
     */
    public function toAsn1(): AbstractType
    {
        $this->controlValue = Asn1::sequence(
            Asn1::integer($this->flags),
            Asn1::integer($this->maxBytes),
            Asn1::octetString($this->cookie)
        );

        return parent::toAsn1();
    }
}
