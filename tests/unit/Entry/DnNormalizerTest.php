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

namespace Tests\Unit\FreeDSx\Ldap\Entry;

use FreeDSx\Ldap\Entry\DnNormalizer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DnNormalizerTest extends TestCase
{
    public function test_empty_dn_canonicalizes_to_empty_string(): void
    {
        self::assertSame(
            '',
            DnNormalizer::canonicalize(''),
        );
    }

    public function test_it_folds_attribute_names_and_values_to_lower_case(): void
    {
        self::assertSame(
            'cn=foo,dc=example,dc=com',
            DnNormalizer::canonicalize('CN=Foo,DC=Example,DC=Com'),
        );
    }

    public function test_it_collapses_insignificant_whitespace_in_values(): void
    {
        self::assertSame(
            'cn=john smith,dc=example,dc=com',
            DnNormalizer::canonicalize('cn=John  Smith,dc=example,dc=com'),
        );
    }

    public function test_it_removes_whitespace_around_separators(): void
    {
        self::assertSame(
            'cn=foo,dc=bar',
            DnNormalizer::canonicalize('cn = foo , dc = bar'),
        );
    }

    public function test_multivalued_rdn_components_are_order_independent(): void
    {
        self::assertSame(
            DnNormalizer::canonicalize('cn=a+uid=b,dc=com'),
            DnNormalizer::canonicalize('uid=b+cn=a,dc=com'),
        );
    }

    public function test_rdn_order_is_significant(): void
    {
        self::assertNotSame(
            DnNormalizer::canonicalize('cn=a,dc=b'),
            DnNormalizer::canonicalize('dc=b,cn=a'),
        );
    }

    public function test_escaped_comma_in_value_is_preserved(): void
    {
        self::assertSame(
            'cn=doe\2cjohn,dc=example,dc=com',
            DnNormalizer::canonicalize('cn=Doe\,John,dc=Example,dc=Com'),
        );
    }

    public function test_the_two_spellings_of_an_escaped_comma_share_one_canonical_form(): void
    {
        self::assertSame(
            DnNormalizer::canonicalize('cn=doe\,john,dc=x'),
            DnNormalizer::canonicalize('cn=doe\2cjohn,dc=x'),
        );
    }

    public function test_an_escaped_comma_stays_distinct_from_an_rdn_separator(): void
    {
        self::assertNotSame(
            DnNormalizer::canonicalize('cn=doe\2cjohn,dc=x'),
            DnNormalizer::canonicalize('cn=doe,john=x,dc=x'),
        );
    }

    public function test_a_hex_escape_resolves_to_the_character_it_encodes(): void
    {
        self::assertSame(
            DnNormalizer::canonicalize('cn=admin,dc=x'),
            DnNormalizer::canonicalize('cn=\61dmin,dc=x'),
        );
    }

    /**
     * @param non-empty-string $dn
     */
    #[DataProvider('invisiblyDifferentDnProvider')]
    public function test_a_dn_differing_only_by_a_code_point_that_renders_as_nothing_is_one_key(string $dn): void
    {
        self::assertSame(
            DnNormalizer::canonicalize('cn=admin,dc=x'),
            DnNormalizer::canonicalize($dn),
        );
    }

    /**
     * The canonical form is the authorization key, so a second key here is an ACL rule that misses its entry.
     *
     * @return iterable<string, array{non-empty-string}>
     */
    public static function invisiblyDifferentDnProvider(): iterable
    {
        yield 'left to right mark' => [
            "cn=adm\u{200E}in,dc=x",
        ];
        yield 'right to left mark' => [
            "cn=adm\u{200F}in,dc=x",
        ];
        yield 'left to right embedding' => [
            "cn=adm\u{202A}in,dc=x",
        ];
        yield 'soft hyphen' => [
            "cn=adm\u{00AD}in,dc=x",
        ];
        yield 'zero width space' => [
            "cn=adm\u{200B}in,dc=x",
        ];
        yield 'object replacement character' => [
            "cn=adm\u{FFFC}in,dc=x",
        ];
        // The ascii shortcut bypasses the prep profile, so it needs the same mapping.
        yield 'ascii control below the line breaks' => [
            "cn=adm\x01in,dc=x",
        ];
        yield 'ascii control above the line breaks' => [
            "cn=adm\x1Fin,dc=x",
        ];
        yield 'delete' => [
            "cn=adm\x7Fin,dc=x",
        ];
    }

    /**
     * RFC 4518 2.2 maps NUL to nothing, so the escaped form names the same entry. The raw byte is refused as
     * invalid syntax instead, which is where the grammar draws the line.
     */
    public function test_an_escaped_null_byte_names_the_same_entry(): void
    {
        self::assertSame(
            DnNormalizer::canonicalize('cn=ab,dc=x'),
            DnNormalizer::canonicalize("cn=a\\00b,dc=x"),
        );
    }

    public function test_malformed_dn_falls_back_to_lowercase_without_throwing(): void
    {
        self::assertSame(
            'not-a-valid-dn',
            DnNormalizer::canonicalize('Not-A-Valid-DN'),
        );
    }
}
