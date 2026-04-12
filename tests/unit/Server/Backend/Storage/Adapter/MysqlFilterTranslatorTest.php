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

    public function test_present_filter_returns_json_contains_path(): void
    {
        $result = $this->subject->translate(new PresentFilter('cn'));

        self::assertNotNull($result);
        self::assertSame(
            "JSON_CONTAINS_PATH(attributes, 'one', '$.\"cn\"')",
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
            '$."objectclass"',
            $result->sql,
        );
        self::assertStringNotContainsString(
            '$."objectClass"',
            $result->sql,
        );
    }

    public function test_equality_filter_returns_json_table_exists(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'cn',
            'Alice',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            '$."cn".values[*]',
            $result->sql,
        );
        self::assertStringContainsString(
            'lower(val) = lower(?)',
            $result->sql,
        );
        self::assertSame(
            ['Alice'],
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
            'JSON_TABLE',
            $result->sql,
        );
        self::assertStringContainsString(
            'lower(val) = lower(?)',
            $result->sql,
        );
        self::assertSame(
            ['Alice'],
            $result->params,
        );
    }

    public function test_approximate_filter_is_marked_inexact(): void
    {
        $result = $this->subject->translate(new ApproximateFilter(
            'cn',
            'Alice',
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

    public function test_substring_with_non_ascii_fragment_is_inexact(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'Café',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_gte_filter_returns_json_table_gte(): void
    {
        $result = $this->subject->translate(new GreaterThanOrEqualFilter(
            'age',
            '30',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            '$."age".values[*]',
            $result->sql,
        );
        self::assertStringContainsString(
            'lower(val) >= lower(?)',
            $result->sql,
        );
        self::assertSame(
            ['30'],
            $result->params,
        );
        self::assertFalse($result->isExact);
    }

    public function test_lte_filter_returns_json_table_lte(): void
    {
        $result = $this->subject->translate(new LessThanOrEqualFilter(
            'age',
            '50',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            '$."age".values[*]',
            $result->sql,
        );
        self::assertStringContainsString(
            'lower(val) <= lower(?)',
            $result->sql,
        );
        self::assertSame(
            ['50'],
            $result->params,
        );
        self::assertFalse($result->isExact);
    }

    public function test_attribute_with_option_strips_option_from_json_path(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'userCertificate;binary',
            'x',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            '$."usercertificate"',
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
            '$."cn"',
            $result->sql,
        );
        self::assertStringNotContainsString(
            ';',
            $result->sql,
        );
    }

    public function test_numericoid_attribute_translates_with_quoted_path(): void
    {
        $result = $this->subject->translate(new PresentFilter('2.5.4.3'));

        self::assertNotNull($result);
        self::assertSame(
            "JSON_CONTAINS_PATH(attributes, 'one', '$.\"2.5.4.3\"')",
            $result->sql,
        );
    }

    public function test_numericoid_equality_translates_with_quoted_path(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            '2.5.4.3',
            'Alice',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            '$."2.5.4.3".values[*]',
            $result->sql,
        );
        self::assertSame(
            ['Alice'],
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

    public function test_substring_with_starts_with_only(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'Al',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            'JSON_TABLE',
            $result->sql,
        );
        self::assertStringContainsString(
            '$."cn".values[*]',
            $result->sql,
        );
        self::assertSame(
            ['Al%'],
            $result->params,
        );
    }

    public function test_substring_with_contains_and_anchors_is_not_exact(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'A',
            'e',
            'lic',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_substring_with_contains_and_starts_with_is_not_exact(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'Alice',
            null,
            'lic',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_substring_with_contains_and_ends_with_is_not_exact(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            null,
            'ice',
            'lic',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_substring_with_single_contains_only_is_exact(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            null,
            null,
            'lic',
        ));

        self::assertNotNull($result);
        self::assertTrue($result->isExact);
    }

    public function test_substring_with_starts_and_ends_without_contains_is_exact(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'A',
            'e',
        ));

        self::assertNotNull($result);
        self::assertTrue($result->isExact);
    }

    public function test_substring_with_multiple_contains_is_not_exact(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'a',
            'd',
            'b',
            'c',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_substring_with_all_components(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            'A',
            'e',
            'lic',
        ));

        self::assertNotNull($result);
        self::assertSame(
            ['A%', '%lic%', '%e'],
            $result->params,
        );
        self::assertStringContainsString(
            'AND',
            $result->sql,
        );
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
        self::assertSame(
            "NOT (JSON_CONTAINS_PATH(attributes, 'one', '$.\"cn\"'))",
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
            "JSON_CONTAINS_PATH(attributes, 'one', '$.\"cn\"')",
            $result->sql,
        );
        self::assertSame(
            ['Alice'],
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
            ['Alice', 'person'],
            $result->params,
        );
    }
}
