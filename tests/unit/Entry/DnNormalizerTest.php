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

    public function test_a_null_byte_does_not_collapse_two_distinct_dns(): void
    {
        self::assertNotSame(
            DnNormalizer::canonicalize("cn=a\\00b,dc=x"),
            DnNormalizer::canonicalize('cn=ab,dc=x'),
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
