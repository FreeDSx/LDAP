<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Encoder\BerEncoder;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Entry\Entry;
use function chr;
use function ord;
use function strlen;

/**
 * Applies some LDAP specific rules, and mappings, to the BER encoder, specified in RFC 4511.
 *
 *    - Only the definite form of length encoding is used.
 *    - OCTET STRING values are encoded in the primitive form only.
 *    - If the value of a BOOLEAN type is true, the encoding of the value octet is set to hex "FF".
 *    - If a value of a type is its default value, it is absent.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapEncoder extends BerEncoder
{
    private const TAG_OCTET_STRING = "\x04";
    private const TAG_INTEGER = "\x02";
    private const TAG_SEQUENCE = "\x30";
    private const TAG_SET = "\x31";
    private const TAG_SEARCH_RESULT_ENTRY = "\x64";

    /**
     * {@inheritdoc}
     */
    public function __construct()
    {
        parent::__construct([
            'primitive_only' => [
                AbstractType::TAG_TYPE_OCTET_STRING,
            ],
        ]);
        $this->setTagMap(AbstractType::TAG_CLASS_APPLICATION, [
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
        ]);
    }

    /**
     * Hand-rolled BER writer for the full LDAPMessage envelope wrapping a SearchResultEntry.
     *
     * Produces byte-for-byte the same output as encode(toAsn1()) but without allocating an ASN.1
     * AST for every entry. This is the server's hot path during large search result delivery.
     *
     * @throws EncoderException
     */
    public function encodeSearchResultEntryMessage(
        int $messageId,
        Entry $entry,
    ): string {
        $innerPayload = $this->berOctetString($entry->getDn()->toString())
            . $this->berWrap(
                self::TAG_SEQUENCE,
                $this->berPartialAttributes($entry),
            );

        $protocolOp = $this->berWrap(
            self::TAG_SEARCH_RESULT_ENTRY,
            $innerPayload,
        );

        $outerPayload = $this->berInteger($messageId) . $protocolOp;

        return $this->berWrap(
            self::TAG_SEQUENCE,
            $outerPayload,
        );
    }

    private function berPartialAttributes(Entry $entry): string
    {
        $out = '';

        foreach ($entry->getAttributes() as $attribute) {
            $valuesPayload = '';
            foreach ($attribute->getValues() as $value) {
                $valuesPayload .= $this->berOctetString($value);
            }

            $partialPayload = $this->berOctetString($attribute->getDescription())
                . $this->berWrap(self::TAG_SET, $valuesPayload);

            $out .= $this->berWrap(
                self::TAG_SEQUENCE,
                $partialPayload,
            );
        }

        return $out;
    }

    private function berOctetString(string $value): string
    {
        return self::TAG_OCTET_STRING
            . $this->berLength(strlen($value))
            . $value;
    }

    private function berWrap(string $tagByte, string $payload): string
    {
        return $tagByte
            . $this->berLength(strlen($payload))
            . $payload;
    }

    /**
     * Encode a non-negative int as an ASN.1 INTEGER (RFC 4511 message IDs are 0 .. 2^31 - 1).
     * Matches BerEncoder::encodeInteger() byte-for-byte for non-negative values.
     *
     * @throws EncoderException
     */
    private function berInteger(int $n): string
    {
        if ($n < 0) {
            throw new EncoderException('Negative integers are not supported on the fast path.');
        }

        if ($n === 0) {
            return self::TAG_INTEGER . "\x01\x00";
        }

        $bytes = '';
        $v = $n;
        while ($v > 0) {
            $bytes = chr($v & 0xff) . $bytes;
            $v >>= 8;
        }

        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return self::TAG_INTEGER
            . $this->berLength(strlen($bytes))
            . $bytes;
    }

    /**
     * @param int<0, max> $length
     */
    private function berLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        $bytes = '';
        $v = $length;
        while ($v > 0) {
            $bytes = chr($v & 0xff) . $bytes;
            $v >>= 8;
        }

        return chr((0x80 | strlen($bytes)) & 0xff) . $bytes;
    }
}
