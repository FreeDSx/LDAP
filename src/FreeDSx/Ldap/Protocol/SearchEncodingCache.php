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

namespace FreeDSx\Ldap\Protocol;

use function chr;
use function strlen;

/**
 * Per-response memo of pre-encoded OCTET STRING bytes for attribute descriptions used when
 * streaming SearchResultEntry messages. Descriptions are a bounded set (schema-defined) that
 * recur across every entry in a large result, so encoding them once per response measurably
 * cuts per-entry CPU.
 *
 * Value caching was tried and reverted: value cardinality is high enough in real workloads that
 * the hashtable + threshold-check overhead outweighed the hits.
 *
 * Lifetime is a single LdapQueue::sendLdapMessage() call. No cross-request state.
 */
final class SearchEncodingCache
{
    private const TAG_OCTET_STRING = "\x04";

    /**
     * @var array<string, string>
     */
    private array $descriptions = [];

    public function description(string $description): string
    {
        return $this->descriptions[$description]
            ??= self::encodeOctetString($description);
    }

    private static function encodeOctetString(string $value): string
    {
        $length = strlen($value);

        if ($length < 128) {
            return self::TAG_OCTET_STRING . chr($length) . $value;
        }

        $lenBytes = '';
        $v = $length;
        while ($v > 0) {
            $lenBytes = chr($v & 0xff) . $lenBytes;
            $v >>= 8;
        }

        return self::TAG_OCTET_STRING
            . chr((0x80 | strlen($lenBytes)) & 0xff)
            . $lenBytes
            . $value;
    }
}
