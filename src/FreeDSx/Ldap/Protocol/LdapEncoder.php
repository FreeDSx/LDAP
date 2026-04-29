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
        parent::__construct();
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
     * AST for every entry, and with the short-form length prefix inlined at every call site so
     * the per-entry encode is a flat sequence of concatenations with no helper-method overhead.
     * This is the server's hot path during large search result delivery.
     *
     * @throws EncoderException
     */
    public function encodeSearchResultEntryMessage(
        int $messageId,
        Entry $entry,
        ?SearchEncodingCache $cache = null,
    ): string {
        $partials = '';

        foreach ($entry->getAttributes() as $attribute) {
            $valuesPayload = '';
            foreach ($attribute->getValues() as $value) {
                $vlen = strlen($value);
                $valuesPayload .= $vlen < 128
                    ? self::TAG_OCTET_STRING . chr($vlen) . $value
                    : self::TAG_OCTET_STRING . $this->berLongLength($vlen) . $value;
            }

            $setLen = strlen($valuesPayload);
            $valuesSet = $setLen < 128
                ? self::TAG_SET . chr($setLen) . $valuesPayload
                : self::TAG_SET . $this->berLongLength($setLen) . $valuesPayload;

            if ($cache !== null) {
                $description = $cache->description($attribute->getDescription());
            } else {
                $desc = $attribute->getDescription();
                $descLen = strlen($desc);
                $description = $descLen < 128
                    ? self::TAG_OCTET_STRING . chr($descLen) . $desc
                    : self::TAG_OCTET_STRING . $this->berLongLength($descLen) . $desc;
            }

            $partial = $description . $valuesSet;
            $plen = strlen($partial);
            $partials .= $plen < 128
                ? self::TAG_SEQUENCE . chr($plen) . $partial
                : self::TAG_SEQUENCE . $this->berLongLength($plen) . $partial;
        }

        $dn = $entry->getDn()->toString();
        $dnLen = strlen($dn);
        $allLen = strlen($partials);

        $inner = (
            $dnLen < 128
                ? self::TAG_OCTET_STRING . chr($dnLen) . $dn
                : self::TAG_OCTET_STRING . $this->berLongLength($dnLen) . $dn
        ) . (
            $allLen < 128
                ? self::TAG_SEQUENCE . chr($allLen) . $partials
                : self::TAG_SEQUENCE . $this->berLongLength($allLen) . $partials
        );
        $innerLen = strlen($inner);

        $protocolOp = $innerLen < 128
            ? self::TAG_SEARCH_RESULT_ENTRY . chr($innerLen) . $inner
            : self::TAG_SEARCH_RESULT_ENTRY . $this->berLongLength($innerLen) . $inner;

        $outer = $this->berInteger($messageId) . $protocolOp;
        $outerLen = strlen($outer);

        return $outerLen < 128
            ? self::TAG_SEQUENCE . chr($outerLen) . $outer
            : self::TAG_SEQUENCE . $this->berLongLength($outerLen) . $outer;
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

        $bl = strlen($bytes);

        return self::TAG_INTEGER
            . ($bl < 128 ? chr($bl) : $this->berLongLength($bl))
            . $bytes;
    }

    /**
     * Long-form definite length octets for lengths >= 128. Cold path; the short form is inlined.
     *
     * @param int<128, max> $length
     */
    private function berLongLength(int $length): string
    {
        $bytes = '';
        $v = $length;
        while ($v > 0) {
            $bytes = chr($v & 0xff) . $bytes;
            $v >>= 8;
        }

        return chr((0x80 | strlen($bytes)) & 0xff) . $bytes;
    }
}
