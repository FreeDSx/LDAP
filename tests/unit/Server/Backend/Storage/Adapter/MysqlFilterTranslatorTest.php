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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\MysqlFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;
use PHPUnit\Framework\TestCase;

final class MysqlFilterTranslatorTest extends TestCase
{
    private MysqlFilterTranslator $subject;

    protected function setUp(): void
    {
        $this->subject = new MysqlFilterTranslator();
    }

    public function test_present_filter_returns_sidecar_presence_exists(): void
    {
        $result = $this->subject->translate(new PresentFilter('cn'));

        self::assertNotNull($result);
        self::assertStringContainsString(
            'FROM entry_attribute_values s',
            $result->sql,
        );
        self::assertStringContainsString(
            "s.attr_name_lower = 'cn'",
            $result->sql,
        );
        self::assertStringStartsWith(
            'lc_dn IN (SELECT s.entry_lc_dn',
            $result->sql,
        );
        self::assertSame(
            [],
            $result->params,
        );
        self::assertTrue($result->isExact);
    }

    public function test_present_filter_lowercases_attribute_name(): void
    {
        $result = $this->subject->translate(new PresentFilter('objectClass'));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.attr_name_lower = 'objectclass'",
            $result->sql,
        );
    }

    public function test_equality_filter_emits_sidecar_value_equality(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'cn',
            'Alice',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.attr_name_lower = 'cn'",
            $result->sql,
        );
        self::assertStringContainsString(
            's.value_lower = ?',
            $result->sql,
        );
        self::assertSame(
            ['alice'],
            $result->params,
        );
        self::assertTrue($result->isExact);
    }

    public function test_approximate_filter_translates_same_as_equality(): void
    {
        $result = $this->subject->translate(new ApproximateFilter(
            'cn',
            'Alice',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            's.value_lower = ?',
            $result->sql,
        );
        self::assertSame(
            ['alice'],
            $result->params,
        );
    }

    public function test_approximate_filter_with_ascii_value_is_exact(): void
    {
        $result = $this->subject->translate(new ApproximateFilter(
            'cn',
            'Alice',
        ));

        self::assertNotNull($result);
        self::assertTrue($result->isExact);
    }

    public function test_approximate_filter_with_non_ascii_value_is_inexact(): void
    {
        $result = $this->subject->translate(new ApproximateFilter(
            'cn',
            'Café',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_equality_filter_with_non_ascii_value_is_inexact(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'cn',
            'Café',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_equality_with_long_value_is_inexact(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'cn',
            str_repeat('a', 256),
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_equality_lowercased_query_value_is_truncated_to_255_chars(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'cn',
            str_repeat('A', 300),
        ));

        self::assertNotNull($result);
        self::assertSame(
            [str_repeat('a', 255)],
            $result->params,
        );
    }

    public function test_substring_with_non_ascii_fragment_is_inexact(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'Café',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_gte_filter_emits_sidecar_value_gte(): void
    {
        $result = $this->subject->translate(new GreaterThanOrEqualFilter(
            'age',
            '30',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.attr_name_lower = 'age'",
            $result->sql,
        );
        self::assertStringContainsString(
            's.value_lower >= ?',
            $result->sql,
        );
        self::assertSame(
            ['30'],
            $result->params,
        );
    }

    public function test_gte_filter_with_digit_value_is_inexact(): void
    {
        $result = $this->subject->translate(new GreaterThanOrEqualFilter(
            'uidNumber',
            '100',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_gte_filter_with_ascii_non_digit_value_is_exact(): void
    {
        $result = $this->subject->translate(new GreaterThanOrEqualFilter(
            'sn',
            'Smith',
        ));

        self::assertNotNull($result);
        self::assertTrue($result->isExact);
    }

    public function test_gte_filter_with_non_ascii_value_is_inexact(): void
    {
        $result = $this->subject->translate(new GreaterThanOrEqualFilter(
            'sn',
            'Smíth',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_lte_filter_emits_sidecar_value_lte(): void
    {
        $result = $this->subject->translate(new LessThanOrEqualFilter(
            'age',
            '50',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.attr_name_lower = 'age'",
            $result->sql,
        );
        self::assertStringContainsString(
            's.value_lower <= ?',
            $result->sql,
        );
        self::assertSame(
            ['50'],
            $result->params,
        );
    }

    public function test_lte_filter_is_always_inexact_under_sidecar_truncation(): void
    {
        $result = $this->subject->translate(new LessThanOrEqualFilter(
            'sn',
            'Smith',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_attribute_with_option_strips_option_from_sql(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'userCertificate;binary',
            'x',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.attr_name_lower = 'usercertificate'",
            $result->sql,
        );
        self::assertStringNotContainsString(
            ';binary',
            $result->sql,
        );
    }

    public function test_attribute_with_multiple_options_strips_all_options(): void
    {
        $result = $this->subject->translate(new PresentFilter('cn;lang-en;binary'));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.attr_name_lower = 'cn'",
            $result->sql,
        );
        self::assertStringNotContainsString(
            ';',
            $result->sql,
        );
    }

    public function test_numericoid_attribute_translates(): void
    {
        $result = $this->subject->translate(new PresentFilter('2.5.4.3'));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.attr_name_lower = '2.5.4.3'",
            $result->sql,
        );
    }

    public function test_numericoid_equality_translates(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            '2.5.4.3',
            'Alice',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.attr_name_lower = '2.5.4.3'",
            $result->sql,
        );
        self::assertSame(
            ['alice'],
            $result->params,
        );
    }

    /**
     * @dataProvider provideInvalidAttributeDescriptions
     */
    public function test_invalid_attribute_description_throws(string $attribute): void
    {
        $this->expectException(InvalidAttributeException::class);

        $this->subject->translate(new EqualityFilter(
            $attribute,
            'x',
        ));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function provideInvalidAttributeDescriptions(): array
    {
        return [
            'empty string'              => [''],
            'starts with digit'         => ['2cn'],
            'starts with hyphen'        => ['-cn'],
            'contains space'            => ['cn name'],
            'contains at-sign'          => ['cn@dc'],
            'contains equals'           => ['cn=value'],
            'contains single quote'     => ["cn'"],
            'sql injection'             => ["cn'; DROP TABLE entries--"],
            'null byte'                 => ["cn\0bad"],
            'non-ascii unicode'         => ['ñame'],
            'trailing semicolon'        => ['cn;'],
            'double semicolon'          => ['cn;;lang'],
            'option with special chars' => ['cn;lang@en'],
        ];
    }

    public function test_substring_with_no_components_returns_null(): void
    {
        $result = $this->subject->translate(new SubstringFilter('cn'));

        self::assertNull($result);
    }

    public function test_substring_with_starts_with_only_emits_prefix_like(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'Al',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.value_lower LIKE ? ESCAPE '!'",
            $result->sql,
        );
        self::assertSame(
            ['al%'],
            $result->params,
        );
        self::assertTrue($result->isExact);
    }

    public function test_substring_with_ends_with_only_falls_back_to_presence(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            null,
            'ce',
        ));

        self::assertNotNull($result);
        self::assertStringNotContainsString(
            'LIKE',
            $result->sql,
        );
        self::assertStringContainsString(
            "s.attr_name_lower = 'cn'",
            $result->sql,
        );
        self::assertSame(
            [],
            $result->params,
        );
        self::assertFalse($result->isExact);
    }

    public function test_substring_with_single_contains_falls_back_to_presence(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            null,
            null,
            'lic',
        ));

        self::assertNotNull($result);
        self::assertStringNotContainsString(
            'LIKE',
            $result->sql,
        );
        self::assertFalse($result->isExact);
    }

    public function test_substring_with_all_fragments_uses_prefix_only(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'A',
            'e',
            'lic',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.value_lower LIKE ? ESCAPE '!'",
            $result->sql,
        );
        self::assertSame(
            ['a%'],
            $result->params,
        );
        self::assertFalse($result->isExact);
    }

    public function test_substring_escapes_special_like_characters(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'al%ice',
        ));

        self::assertNotNull($result);
        self::assertSame(
            ['al!%ice%'],
            $result->params,
        );
    }

    public function test_and_filter_all_translatable_returns_combined(): void
    {
        $result = $this->subject->translate(new AndFilter(
            new PresentFilter('cn'),
            new EqualityFilter(
                'objectClass',
                'person',
            ),
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            ' AND ',
            $result->sql,
        );
        self::assertSame(
            ['person'],
            $result->params,
        );
        self::assertTrue($result->isExact);
    }

    public function test_and_filter_partial_translatable_is_not_exact(): void
    {
        $result = $this->subject->translate(new AndFilter(
            new PresentFilter('cn'),
            new MatchingRuleFilter(
                '1.2.840.113556.1.4.803',
                'memberOf',
                '2',
            ),
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
        self::assertSame(
            [],
            $result->params,
        );
    }

    public function test_and_filter_with_no_translatable_children_returns_null(): void
    {
        $result = $this->subject->translate(new AndFilter(
            new MatchingRuleFilter(
                '1.2.840.113556.1.4.803',
                'memberOf',
                '2',
            ),
        ));

        self::assertNull($result);
    }

    public function test_or_filter_all_translatable_is_exact(): void
    {
        $result = $this->subject->translate(new OrFilter(
            new PresentFilter('cn'),
            new EqualityFilter(
                'objectClass',
                'person',
            ),
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            ' OR ',
            $result->sql,
        );
        self::assertTrue($result->isExact);
    }

    public function test_or_filter_with_one_untranslatable_child_returns_null(): void
    {
        $result = $this->subject->translate(new OrFilter(
            new PresentFilter('cn'),
            new MatchingRuleFilter(
                '1.2.840.113556.1.4.803',
                'memberOf',
                '2',
            ),
        ));

        self::assertNull($result);
    }

    public function test_not_filter_with_translatable_child_returns_not_sql(): void
    {
        $result = $this->subject->translate(
            new NotFilter(new PresentFilter('cn')),
        );

        self::assertNotNull($result);
        self::assertStringStartsWith(
            'NOT (',
            $result->sql,
        );
        self::assertSame(
            [],
            $result->params,
        );
        self::assertTrue($result->isExact);
    }

    public function test_not_present_emits_plain_not_without_presence_guard(): void
    {
        $result = $this->subject->translate(
            new NotFilter(new PresentFilter('cn')),
        );

        self::assertNotNull($result);
        self::assertStringStartsWith(
            'NOT (lc_dn IN (',
            $result->sql,
        );
        self::assertStringContainsString(
            "s.attr_name_lower = 'cn'",
            $result->sql,
        );
    }

    public function test_not_equality_adds_presence_guard(): void
    {
        $result = $this->subject->translate(
            new NotFilter(new EqualityFilter(
                'cn',
                'Alice',
            )),
        );

        self::assertNotNull($result);
        self::assertStringStartsWith(
            '(NOT (',
            $result->sql,
        );
        self::assertStringContainsString(
            "s.attr_name_lower = 'cn'",
            $result->sql,
        );
        self::assertSame(
            ['alice'],
            $result->params,
        );
        self::assertTrue($result->isExact);
    }

    public function test_not_equality_with_non_ascii_value_is_inexact(): void
    {
        $result = $this->subject->translate(
            new NotFilter(new EqualityFilter(
                'cn',
                'Café',
            )),
        );

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_not_composite_inner_is_inexact(): void
    {
        $result = $this->subject->translate(
            new NotFilter(new AndFilter(
                new EqualityFilter(
                    'cn',
                    'Alice',
                ),
                new EqualityFilter(
                    'sn',
                    'Smith',
                ),
            )),
        );

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
        self::assertStringStartsWith(
            'NOT (',
            $result->sql,
        );
    }

    public function test_not_filter_with_untranslatable_child_returns_null(): void
    {
        $result = $this->subject->translate(
            new NotFilter(new MatchingRuleFilter(
                '1.2.840.113556.1.4.803',
                'memberOf',
                '2',
            )),
        );

        self::assertNull($result);
    }

    public function test_matching_rule_filter_always_returns_null(): void
    {
        $result = $this->subject->translate(
            new MatchingRuleFilter(
                '1.2.840.113556.1.4.803',
                'memberOf',
                '2',
            ),
        );

        self::assertNull($result);
    }

    public function test_and_params_are_merged_in_order(): void
    {
        $result = $this->subject->translate(new AndFilter(
            new EqualityFilter(
                'cn',
                'Alice',
            ),
            new EqualityFilter(
                'objectClass',
                'person',
            ),
        ));

        self::assertNotNull($result);
        self::assertSame(
            ['alice', 'person'],
            $result->params,
        );
    }
}
