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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class LdapEncoderSearchResultEntryTest extends TestCase
{
    private LdapEncoder $encoder;

    protected function setUp(): void
    {
        $this->encoder = new LdapEncoder();
    }

    public function test_entry_with_no_attributes(): void
    {
        $this->assertParity(
            messageId: 1,
            entry: new Entry(new Dn('dc=foo,dc=bar')),
        );
    }

    public function test_single_attribute_single_ascii_value(): void
    {
        $this->assertParity(
            messageId: 2,
            entry: new Entry(
                new Dn('cn=alice,dc=example,dc=com'),
                new Attribute('cn', 'alice'),
            ),
        );
    }

    public function test_multi_value_attribute(): void
    {
        $this->assertParity(
            messageId: 3,
            entry: new Entry(
                new Dn('cn=bob,dc=example,dc=com'),
                new Attribute(
                    'objectClass',
                    'top',
                    'person',
                    'organizationalPerson',
                    'inetOrgPerson',
                ),
            ),
        );
    }

    public function test_multiple_attributes(): void
    {
        $this->assertParity(
            messageId: 4,
            entry: new Entry(
                new Dn('cn=carol,dc=example,dc=com'),
                new Attribute('cn', 'carol'),
                new Attribute('sn', 'Smith'),
                new Attribute('mail', 'carol@example.com'),
                new Attribute('objectClass', 'top', 'person'),
            ),
        );
    }

    public function test_attribute_description_with_options(): void
    {
        $this->assertParity(
            messageId: 5,
            entry: new Entry(
                new Dn('cn=dave,dc=example,dc=com'),
                new Attribute('userCertificate;binary', "\x30\x82\x01\x02"),
            ),
        );
    }

    public function test_long_value_pushes_lengths_past_short_form(): void
    {
        $this->assertParity(
            messageId: 6,
            entry: new Entry(
                new Dn('cn=long,dc=example,dc=com'),
                new Attribute('description', str_repeat('x', 200)),
            ),
        );
    }

    public function test_very_long_value_uses_three_byte_length(): void
    {
        $this->assertParity(
            messageId: 7,
            entry: new Entry(
                new Dn('cn=huge,dc=example,dc=com'),
                new Attribute('description', str_repeat('y', 100000)),
            ),
        );
    }

    public function test_multibyte_utf8_dn_and_value(): void
    {
        $this->assertParity(
            messageId: 8,
            entry: new Entry(
                new Dn('cn=日本語,dc=例え,dc=テスト'),
                new Attribute('displayName', 'テスト ユーザー'),
                new Attribute('description', '🚀 emoji value 🔥'),
            ),
        );
    }

    public function test_embedded_null_and_binary_bytes_in_value(): void
    {
        $this->assertParity(
            messageId: 9,
            entry: new Entry(
                new Dn('cn=bin,dc=example,dc=com'),
                new Attribute('userCertificate;binary', "\x00\x01\x02\xff\xfe\xfd\x00"),
            ),
        );
    }

    public function test_message_id_zero(): void
    {
        $this->assertParity(
            messageId: 0,
            entry: new Entry(
                new Dn('dc=root'),
                new Attribute('cn', 'root'),
            ),
        );
    }

    public function test_message_id_127(): void
    {
        $this->assertParity(
            messageId: 127,
            entry: new Entry(
                new Dn('cn=a,dc=b'),
                new Attribute('cn', 'a'),
            ),
        );
    }

    public function test_message_id_128_requires_leading_pad(): void
    {
        $this->assertParity(
            messageId: 128,
            entry: new Entry(
                new Dn('cn=a,dc=b'),
                new Attribute('cn', 'a'),
            ),
        );
    }

    public function test_message_id_32768_three_byte_encoding(): void
    {
        $this->assertParity(
            messageId: 32768,
            entry: new Entry(
                new Dn('cn=a,dc=b'),
                new Attribute('cn', 'a'),
            ),
        );
    }

    public function test_message_id_max_int31(): void
    {
        $this->assertParity(
            messageId: 2147483647,
            entry: new Entry(
                new Dn('cn=a,dc=b'),
                new Attribute('cn', 'a'),
            ),
        );
    }

    public function test_dn_with_escaped_comma_roundtrips_bytes(): void
    {
        $this->assertParity(
            messageId: 10,
            entry: new Entry(
                new Dn('cn=Last\\, First,dc=example,dc=com'),
                new Attribute('cn', 'Last, First'),
            ),
        );
    }

    public function test_empty_attribute_value_set(): void
    {
        $this->assertParity(
            messageId: 11,
            entry: new Entry(
                new Dn('cn=empty,dc=example,dc=com'),
                new Attribute('description'),
            ),
        );
    }

    private function assertParity(
        int $messageId,
        Entry $entry,
    ): void {
        $expected = $this->encoder->encode(
            (new LdapMessageResponse(
                $messageId,
                new SearchResultEntry($entry),
            ))->toAsn1(),
        );

        $actual = $this->encoder->encodeSearchResultEntryMessage(
            $messageId,
            $entry,
        );

        self::assertSame(
            bin2hex($expected),
            bin2hex($actual),
        );
    }
}
