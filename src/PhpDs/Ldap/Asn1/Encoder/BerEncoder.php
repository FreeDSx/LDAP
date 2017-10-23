<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap\Asn1\Encoder;

use PhpDs\Ldap\Asn1\Type\ConstructedTypeInterface;
use PhpDs\Ldap\Asn1\Type\AbstractType;
use PhpDs\Ldap\Asn1\Type\BooleanType;
use PhpDs\Ldap\Asn1\Type\EnumeratedType;
use PhpDs\Ldap\Asn1\Type\IncompleteType;
use PhpDs\Ldap\Asn1\Type\IntegerType;
use PhpDs\Ldap\Asn1\Type\NullType;
use PhpDs\Ldap\Asn1\Type\OctetStringType;
use PhpDs\Ldap\Asn1\Type\SequenceType;
use PhpDs\Ldap\Asn1\Type\AbstractStringType;
use PhpDs\Ldap\Asn1\Type\SetType;
use PhpDs\Ldap\Exception\EncoderException;
use PhpDs\Ldap\Exception\InvalidArgumentException;
use PhpDs\Ldap\Exception\PartialPduException;

/**
 * Basic Encoding Rules (BER) encoder for LDAP. A subset of BER defined in RFC 4511, 5.1:
 *
 *    - Only the definite form of length encoding is used.
 *    - OCTET STRING values are encoded in the primitive form only.
 *    - If the value of a BOOLEAN type is true, the encoding of the value octet is set to hex "FF".
 *    - If a value of a type is its default value, it is absent.
 *
 * Additionally, it is assumed the max integer encoding/decoding value is 2147483647 (32-bit), as defined by maxInt.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class BerEncoder implements EncoderInterface
{
    /**
     * @var array
     */
    protected $appMap = [
        AbstractType::TAG_CLASS_APPLICATION => [
            0 => AbstractType::TAG_TYPE_SEQUENCE,
            1 => AbstractType::TAG_TYPE_SEQUENCE,
            2 => AbstractType::TAG_TYPE_NULL,
            3 => AbstractType::TAG_TYPE_SEQUENCE,
            4 => AbstractType::TAG_TYPE_SEQUENCE,
            5 => AbstractType::TAG_TYPE_SEQUENCE,
            6 => AbstractType::TAG_TYPE_SEQUENCE,
            7 => AbstractType::TAG_TYPE_SEQUENCE,
            8 => AbstractType::TAG_TYPE_SEQUENCE,
            9 => AbstractType::TAG_TYPE_SEQUENCE,
            10 => AbstractType::TAG_TYPE_OCTET_STRING,
            11 => AbstractType::TAG_TYPE_SEQUENCE,
            12 => AbstractType::TAG_TYPE_SEQUENCE,
            13 => AbstractType::TAG_TYPE_SEQUENCE,
            14 => AbstractType::TAG_TYPE_SEQUENCE,
            15 => AbstractType::TAG_TYPE_SEQUENCE,
            16 => AbstractType::TAG_TYPE_INTEGER,
            19 => AbstractType::TAG_TYPE_SEQUENCE,
            23 => AbstractType::TAG_TYPE_SEQUENCE,
            24 => AbstractType::TAG_TYPE_SEQUENCE,
            25 => AbstractType::TAG_TYPE_SEQUENCE,
        ],
        AbstractType::TAG_CLASS_CONTEXT_SPECIFIC => [],
        AbstractType::TAG_CLASS_PRIVATE => [],
    ];

    /**
     * {@inheritdoc}
     */
    public function decode($binary, array $tagMap = []) : AbstractType
    {
        if ($binary == '') {
            throw new InvalidArgumentException('The data to decode cannot be empty.');
        } elseif (strlen($binary) === 1) {
            throw new PartialPduException('Received only 1 byte of data.');
        }
        $info = $this->decodeBytes($binary, $tagMap, true);
        $info['type']->setTrailingData($info['bytes']);

        return $info['type'];
    }


    /**
     * {@inheritdoc}
     */
    public function complete(IncompleteType $type, int $tagType, array $tagMap = []) : AbstractType
    {
        return $this->getDecodedType($tagType, $type->getValue(), $tagMap)
             ->setTagNumber($type->getTagNumber())
             ->setTagClass($type->getTagClass());
    }

    /**
     * {@inheritdoc}
     */
    public function encode(AbstractType $type) : string
    {
        $tag = $type->getTagClass() | $type->getTagNumber() | ($type instanceof ConstructedTypeInterface ? 0x20 : 0);
        $valueBytes = $this->getEncodedValue($type);
        $lengthBytes = $this->getEncodedLength(strlen($valueBytes));

        return chr($tag).$lengthBytes.$valueBytes;
    }

    /**
     * Map universal types to specific tag class values when decoding.
     *
     * @param int $class
     * @param array $map
     * @return $this
     */
    public function setTypeMap(int $class, array $map)
    {
        if (isset($this->appMap[$class])) {
            $this->appMap[$class] = $map;
        }

        return $this;
    }

    /**
     * @param string $binary
     * @param array $tagMap
     * @param bool $isRoot
     * @return array
     * @throws EncoderException
     * @throws PartialPduException
     */
    protected function decodeBytes($binary, array $tagMap, bool $isRoot = false) : array
    {
        $data = ['type' => null, 'bytes' => null, 'trailing' => null];
        $tagMap = $tagMap + $this->appMap;

        $tag = $this->getDecodedTag(ord($binary[0]));
        $length = $this->getDecodedLength(substr($binary, 1));
        $tagType = $this->getTagType($tag['number'], $tag['class'], $tagMap);

        $totalLength = 1 + $length['length_length'] + $length['value_length'];
        if (strlen($binary) < $totalLength) {
            $message = sprintf(
                'The expected byte length was %s, but received %s.',
                $totalLength,
                strlen($binary)
            );
            if ($isRoot) {
                throw new PartialPduException($message);
            } else {
                throw new EncoderException($message);
            }
        }

        $data['type'] = $this->getDecodedType($tagType, substr($binary, 1 + $length['length_length'], $length['value_length']), $tagMap);
        $data['type']->setTagClass($tag['class']);
        $data['type']->setTagNumber($tag['number']);
        $data['bytes'] = substr($binary, $totalLength);

        return $data;
    }

    /**
     * From a specific tag number and class try to determine what universal ASN1 type it should be mapped to. If there
     * is no mapping defined it will return null. In this case the binary data will be wrapped into an IncompleteType.
     *
     * @param int $tagNumber
     * @param int $tagClass
     * @param array $map
     * @return int|null
     */
    protected function getTagType(int $tagNumber, int $tagClass, array $map) : ?int
    {
        if ($tagClass === AbstractType::TAG_CLASS_UNIVERSAL) {
            return $tagNumber;
        }

        return $map[$tagClass][$tagNumber] ?? null;
    }

    /**
     * @param string $bytes
     * @return array
     * @throws EncoderException
     */
    protected function getDecodedLength($bytes) : array
    {
        $info = ['value_length' => isset($bytes[0]) ? ord($bytes[0]) : 0, 'length_length' => 1];

        # Restricted per the LDAP RFC 4511 section 5.1
        if ($info['value_length'] === 128) {
            throw new EncoderException('Indefinite length encoding is not supported.');
        }

        # Long definite length has a special encoding.
        if ($info['value_length'] > 127) {
            # The length of the length bytes is in the first 7 bits. So remove the MSB to get the value.
            $info['length_length'] = $info['value_length'] & ~0x80;

            # The value of 127 is marked as reserved in the spec
            if ($info['length_length'] === 127) {
                throw new EncoderException('The decoded length cannot be equal to 127 bytes.');
            }
            if ($info['length_length'] + 2 > strlen($bytes)) {
                throw new PartialPduException('Not enough data to decode the length.');
            }

            # Base 256 encoded
            $info['value_length'] = 0;
            for ($i = 1; $i < $info['length_length'] + 1; $i++) {
                $info['value_length'] = $info['value_length'] * 256 + ord($bytes[$i]);
            }

            # Add the byte that represents the length of the length
            $info['length_length']++;
        }

        return $info;
    }

    /**
     * @param $tag
     * @return array
     */
    protected function getDecodedTag(int $tag) : array
    {
        $info = ['class' => null, 'number' => null, 'constructed' => null];

        if ($tag & AbstractType::TAG_CLASS_APPLICATION && $tag & AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
            $info['class'] = AbstractType::TAG_CLASS_PRIVATE;
        } elseif ($tag & AbstractType::TAG_CLASS_APPLICATION) {
            $info['class'] = AbstractType::TAG_CLASS_APPLICATION;
        } elseif ($tag & AbstractType::TAG_CLASS_CONTEXT_SPECIFIC) {
            $info['class'] = AbstractType::TAG_CLASS_CONTEXT_SPECIFIC;
        } else {
            $info['class'] = AbstractType::TAG_CLASS_UNIVERSAL;
        }
        $info['constructed'] = (bool) ($tag & AbstractType::CONSTRUCTED_TYPE);
        $info['number'] = bindec((substr(decbin($tag), -5)));

        return $info;
    }

    /**
     * @param int|null $tagType
     * @param string $bytes
     * @param array $tagMap
     * @return AbstractType
     * @throws EncoderException
     */
    protected function getDecodedType(?int $tagType, $bytes, array $tagMap) : AbstractType
    {
        switch ($tagType) {
            // @todo More strict check? The RFC explicitly states the assumed value, though different from strict BER
            case AbstractType::TAG_TYPE_BOOLEAN:
                $type = new BooleanType(ord($bytes[0]) !== 0);
                break;
            case AbstractType::TAG_TYPE_NULL:
                $type = new NullType();
                break;
            case AbstractType::TAG_TYPE_INTEGER:
                $type = new IntegerType($this->decodeInteger($bytes));
                break;
            case AbstractType::TAG_TYPE_ENUMERATED:
                $type = new EnumeratedType($this->decodeInteger($bytes));
                break;
            case AbstractType::TAG_TYPE_OCTET_STRING:
                $type = new OctetStringType($bytes);
                break;
            case AbstractType::TAG_TYPE_SEQUENCE:
                $type = new SequenceType(...$this->decodeSequence($bytes, $tagMap));
                break;
            case AbstractType::TAG_TYPE_SET:
                $type = new SetType(...$this->decodeSequence($bytes, $tagMap));
                break;
            case null:
                $type = new IncompleteType($bytes);
                break;
            default:
                throw new EncoderException(sprintf('Unable to decode value to a type for tag %s.', $tagType));
        }

        return $type;
    }

    /**
     * @param int $num
     * @return string
     * @throws EncoderException
     */
    protected function getEncodedLength(int $num)
    {
        # Short definite length, nothing to do
        if ($num < 128) {
            return chr($num);
        }
        # Long definite length is base 256 encoded. This seems kinda inefficient. Found on base_convert comments.
        $num = base_convert($num, 10, 2);
        $num = str_pad($num, ceil(strlen($num) / 8) * 8, '0', STR_PAD_LEFT);

        $bytes = '';
        for ($i = strlen($num) - 8; $i >= 0; $i -= 8) {
            $bytes = chr(base_convert(substr($num, $i, 8), 2, 10)).$bytes;
        }

        $length = strlen($bytes);
        if ($length >= 127) {
            throw new EncoderException('The encoded length cannot be greater than or equal to 127 bytes');
        }

        return chr(0x80 | $length).$bytes;
    }

    /**
     * @param AbstractType $type
     * @return string
     * @throws EncoderException
     */
    protected function getEncodedValue(AbstractType $type)
    {
        $bytes = null;

        switch ($type) {
            case $type instanceof BooleanType:
                $bytes = chr($type->getValue() ? 0xFF : 0x00);
                break;
            case $type instanceof IntegerType:
            case $type instanceof EnumeratedType:
                $bytes = $this->encodeInteger($type);
                break;
            case $type instanceof AbstractStringType:
                $bytes = $type->getValue();
                break;
            case $type instanceof ConstructedTypeInterface:
                $bytes = $this->encodeConstructedType($type);
                break;
            case $type instanceof NullType:
                break;
            default:
                throw new EncoderException(sprintf('The type "%s" is not currently supported.', $type));
        }

        return $bytes;
    }

    /**
     * @param $num
     * @return string
     */
    protected function packNumber($num)
    {
        # 8bit
        if ($num <= 255) {
            $size = 'C';
            # 16bit
        } elseif ($num <= 32767) {
            $size = 'n';
            # 32bit
        } else {
            $size = 'N';
        }

        return pack($size, $num);
    }

    /**
     * Kinda ugly, but the LDAP max int is 32bit.
     *
     * @param AbstractType $type
     * @return string
     */
    protected function encodeInteger(AbstractType $type) : string
    {
        $int = abs($type->getValue());
        $isNegative = ($type->getValue() < 0);

        # @todo Shouldn't have to do this...the logic is wrong somewhere below.
        if ($isNegative && $int === 128) {
            return chr(0x80);
        }

        # Subtract one for Two's Complement...
        if ($isNegative) {
            $int = $int - 1;
        }
        $bytes = $this->packNumber($int);

        # Two's Complement, invert the bits...
        if ($isNegative) {
            $len = strlen($bytes);
            for ($i = 0; $i < $len; $i++) {
                $bytes[$i] = ~$bytes[$i];
            }
        }

        # MSB == Most Significant Bit. The one used for the sign.
        $msbSet = (bool) (ord($bytes[0]) & 0x80);
        if (!$isNegative && $msbSet) {
            $bytes = "\x00".$bytes;
        } elseif (($isNegative && !$msbSet) || ($isNegative && ($int <= 127))) {
            $bytes = "\xFF".$bytes;
        }

        return $bytes;
    }

    /**
     * @param string $bytes
     * @return int number
     */
    protected function decodeInteger($bytes) : int
    {
        $isNegative = (ord($bytes[0]) & 0x80);
        $len = strlen($bytes);

        # Cheat a bit...max int in LDAP is 32-bit
        if ($len <= 1) {
            $size = 'C';
        } elseif ($len <= 2) {
            $size = 'n';
        } else {
            $size = 'N';
        }

        # Need to reverse Two's Complement. Invert the bits...
        if ($isNegative) {
            for ($i = 0; $i < $len; $i++) {
                $bytes[$i] = ~$bytes[$i];
            }
        }
        $int = unpack($size."1int", $bytes)['int'];

        # Complete Two's Complement by adding 1 and turning it negative...
        if ($isNegative) {
            $int = ($int + 1) * -1;
        }

        return $int;
    }

    /**
     * @param ConstructedTypeInterface $type
     * @return string
     */
    protected function encodeConstructedType(ConstructedTypeInterface $type) : string
    {
        $bytes = '';

        foreach ($type->getChildren() as $child) {
            $bytes .= $this->encode($child);
        }

        return $bytes;
    }

    protected function decodeSequence($bytes, array $tagMap)
    {
        $sequences = [];

        while ($bytes) {
            list('type' => $type, 'bytes' => $bytes) = $this->decodeBytes($bytes, $tagMap);
            $sequences[] = $type;
        }

        return $sequences;
    }
}
