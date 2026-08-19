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
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqliteFilterTranslator;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\AttributeFilterSupport;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContextInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SqliteFilterTranslatorTest extends TestCase
{
    private SqliteFilterTranslator $subject;

    protected function setUp(): void
    {
        $this->subject = new SqliteFilterTranslator($this->attributeContext());
    }

    public function test_present_emits_sidecar_presence_exists(): void
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
        self::assertSame(
            [],
            $result->params,
        );
    }

    public function test_present_lowercases_attribute_name(): void
    {
        $result = $this->subject->translate(new PresentFilter('objectClass'));

        self::assertNotNull($result);
        self::assertStringContainsString(
            "s.attr_name_lower = 'objectclass'",
            $result->sql,
        );
    }

    public function test_equality_emits_sidecar_value_equality(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
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

    public function test_leaf_correlated_sql_is_an_exists_form(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'cn',
            'Alice',
        ));

        self::assertNotNull($result);
        self::assertNotNull($result->correlatedSql);
        self::assertStringContainsString(
            'EXISTS (',
            $result->correlatedSql,
        );
        self::assertStringContainsString(
            's.entry_lc_dn = lc_dn',
            $result->correlatedSql,
        );
        self::assertStringNotContainsString(
            'lc_dn IN (',
            $result->correlatedSql,
        );
    }

    public function test_and_composes_correlated_exists_with_and(): void
    {
        $result = $this->subject->translate(new AndFilter(
            new EqualityFilter('cn', 'Alice'),
            new EqualityFilter('sn', 'Smith'),
        ));

        self::assertNotNull($result);
        self::assertNotNull($result->correlatedSql);
        self::assertSame(
            2,
            substr_count($result->correlatedSql, 'EXISTS ('),
        );
        self::assertStringContainsString(
            ') AND (',
            $result->correlatedSql,
        );
    }

    public function test_or_composes_correlated_exists_with_or(): void
    {
        $result = $this->subject->translate(new OrFilter(
            new EqualityFilter('cn', 'Alice'),
            new EqualityFilter('cn', 'Bob'),
        ));

        self::assertNotNull($result);
        self::assertNotNull($result->correlatedSql);
        self::assertStringContainsString(
            ') OR (',
            $result->correlatedSql,
        );
    }

    public function test_not_value_correlated_sql_negates_the_value_exists(): void
    {
        $result = $this->subject->translate(new NotFilter(
            new EqualityFilter('cn', 'Alice'),
        ));

        self::assertNotNull($result);
        self::assertNotNull($result->correlatedSql);
        self::assertStringContainsString(
            'NOT (',
            $result->correlatedSql,
        );
        self::assertSame(
            1,
            substr_count($result->correlatedSql, 'EXISTS ('),
        );
    }

    public function test_approximate_translates_same_as_equality(): void
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

    public function test_approximate_with_ascii_value_is_exact(): void
    {
        $result = $this->subject->translate(new ApproximateFilter(
            'cn',
            'Alice',
        ));

        self::assertNotNull($result);
        self::assertTrue($result->isExact);
    }

    public function test_approximate_with_non_ascii_value_is_inexact(): void
    {
        $result = $this->subject->translate(new ApproximateFilter(
            'cn',
            'Café',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_equality_with_ascii_value_is_exact(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'cn',
            'Alice',
        ));

        self::assertNotNull($result);
        self::assertTrue($result->isExact);
    }

    public function test_equality_with_non_ascii_value_is_inexact(): void
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

    public function test_equality_value_is_lowercased_and_truncated(): void
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

    public function test_an_attribute_the_schema_does_not_define_can_never_match(): void
    {
        $result = $this->translateWith(
            new EqualityFilter('shoeSize', '12'),
            $this->attributeContext(support: AttributeFilterSupport::NeverMatches),
        );

        self::assertNotNull($result);
        self::assertSame(
            '1 = 0',
            $result->sql,
        );
        // Undefined only behaves like false until a negation is layered over it, so the evaluator must still run.
        self::assertFalse($result->isExact);
    }

    public function test_negating_an_attribute_the_schema_does_not_define_can_never_match(): void
    {
        $result = $this->translateWith(
            new NotFilter(new EqualityFilter('shoeSize', '12')),
            $this->attributeContext(support: AttributeFilterSupport::NeverMatches),
        );

        self::assertNotNull($result);
        self::assertStringContainsString(
            '1 = 0',
            $result->sql,
        );
    }

    public function test_an_assertion_value_the_syntax_rejects_selects_nothing_and_stays_inexact(): void
    {
        $result = $this->translateWith(
            new EqualityFilter('uidNumber', 'abc'),
            $this->attributeContext(assertionConforms: false),
        );

        self::assertNotNull($result);
        self::assertStringContainsString(
            '1 = 0',
            $result->sql,
        );
        self::assertFalse($result->isExact);
    }

    public function test_a_negated_assertion_the_syntax_rejects_stays_inexact_so_the_evaluator_decides(): void
    {
        $result = $this->translateWith(
            new NotFilter(new EqualityFilter('uidNumber', 'abc')),
            $this->attributeContext(assertionConforms: false),
        );

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_a_substring_filter_is_not_subject_to_the_assertion_syntax_check(): void
    {
        $result = $this->translateWith(
            new SubstringFilter('uidNumber', '1'),
            $this->attributeContext(assertionConforms: false),
        );

        self::assertNotNull($result);
        self::assertStringNotContainsString(
            '1 = 0',
            $result->sql,
        );
    }

    public function test_a_substring_on_a_type_with_no_substring_rule_selects_nothing(): void
    {
        $result = $this->translateWith(
            new SubstringFilter('uidNumber', '1'),
            $this->attributeContext(hasSubstringRule: false),
        );

        self::assertNotNull($result);
        self::assertSame(
            '1 = 0',
            $result->sql,
        );
        self::assertFalse($result->isExact);
    }

    public function test_an_attribute_with_subtypes_is_left_to_the_evaluator(): void
    {
        $result = $this->translateWith(
            new EqualityFilter('name', 'alice'),
            $this->attributeContext(support: AttributeFilterSupport::NeedsEvaluator),
        );

        self::assertNull($result);
    }

    public function test_gte_emits_numeric_cast_for_integer_ordered_attribute(): void
    {
        $result = $this->translateWith(
            new GreaterThanOrEqualFilter('uidNumber', '30'),
            $this->attributeContext(integerOrdered: true),
        );

        self::assertNotNull($result);
        self::assertStringContainsString(
            'CAST(s.value_lower AS INTEGER) >= CAST(? AS INTEGER)',
            $result->sql,
        );
        self::assertTrue($result->isExact);
        self::assertSame(
            ['30'],
            $result->params,
        );
    }

    public function test_gte_emits_lexical_comparison_for_non_integer_attribute(): void
    {
        $result = $this->translateWith(
            new GreaterThanOrEqualFilter('cn', '30'),
            $this->attributeContext(integerOrdered: false),
        );

        self::assertNotNull($result);
        self::assertStringContainsString(
            's.value_lower >= ?',
            $result->sql,
        );
    }

    public function test_gte_with_digit_value_is_inexact(): void
    {
        // Critical: PHP compareOrdered does integer compare when both sides
        // are ctype_digit, so SQL byte compare would diverge. Must stay inexact.
        $result = $this->subject->translate(new GreaterThanOrEqualFilter(
            'uidNumber',
            '100',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_gte_with_ascii_non_digit_value_is_exact(): void
    {
        $result = $this->subject->translate(new GreaterThanOrEqualFilter(
            'sn',
            'Smith',
        ));

        self::assertNotNull($result);
        self::assertTrue($result->isExact);
    }

    public function test_gte_with_non_ascii_value_is_inexact(): void
    {
        $result = $this->subject->translate(new GreaterThanOrEqualFilter(
            'sn',
            'Smíth',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_lte_emits_numeric_cast_for_integer_ordered_attribute(): void
    {
        $result = $this->translateWith(
            new LessThanOrEqualFilter('uidNumber', '50'),
            $this->attributeContext(integerOrdered: true),
        );

        self::assertNotNull($result);
        self::assertStringContainsString(
            'CAST(s.value_lower AS INTEGER) <= CAST(? AS INTEGER)',
            $result->sql,
        );
        self::assertSame(
            ['50'],
            $result->params,
        );
    }

    public function test_lte_is_always_inexact(): void
    {
        $result = $this->subject->translate(new LessThanOrEqualFilter(
            'sn',
            'Smith',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_attribute_with_option_strips_option(): void
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

    public function test_option_bearing_equality_filter_is_inexact(): void
    {
        $result = $this->subject->translate(new EqualityFilter(
            'cn;lang-en',
            'x',
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_option_bearing_present_filter_is_inexact(): void
    {
        $result = $this->subject->translate(new PresentFilter('cn;lang-en'));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
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

    #[DataProvider('provideInvalidAttributeDescriptions')]
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
            'trailing newline'          => ["cn\n"],
            'newline after an option'   => ["cn;binary\n"],
            'newline after a numericoid' => ["2.5.4.3\n"],
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

    public function test_substring_starts_with_only_emits_prefix_like(): void
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

    public function test_contains_uses_the_substring_index_when_present(): void
    {
        $translator = new SqliteFilterTranslator(
            $this->attributeContext(),
            new TrigramSubstringIndex(['cn']),
        );

        $result = $translator->translate(new SubstringFilter(
            'cn',
            null,
            null,
            'smith',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            'entry_attribute_trigrams',
            $result->sql,
        );
        self::assertFalse($result->isExact);
    }

    public function test_suffix_uses_the_substring_index_when_present(): void
    {
        $translator = new SqliteFilterTranslator(
            $this->attributeContext(),
            new TrigramSubstringIndex(['cn']),
        );

        $result = $translator->translate(new SubstringFilter(
            'cn',
            null,
            'ith',
        ));

        self::assertNotNull($result);
        self::assertStringContainsString(
            'entry_attribute_trigrams',
            $result->sql,
        );
        self::assertFalse($result->isExact);
    }

    public function test_contains_falls_back_to_presence_without_a_substring_index(): void
    {
        $result = $this->subject->translate(new SubstringFilter(
            'cn',
            null,
            null,
            'smith',
        ));

        self::assertNotNull($result);
        self::assertStringNotContainsString(
            'entry_attribute_trigrams',
            $result->sql,
        );
    }

    public function test_prefix_ignores_the_substring_index(): void
    {
        $translator = new SqliteFilterTranslator(
            $this->attributeContext(),
            new TrigramSubstringIndex(['cn']),
        );

        $result = $translator->translate(new SubstringFilter(
            'cn',
            'smi',
        ));

        self::assertNotNull($result);
        self::assertStringNotContainsString(
            'entry_attribute_trigrams',
            $result->sql,
        );
        self::assertTrue($result->isExact);
    }

    public function test_substring_ends_with_only_falls_back_to_presence_inexact(): void
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
        self::assertFalse($result->isExact);
        self::assertSame(
            [],
            $result->params,
        );
    }

    public function test_substring_single_contains_falls_back_to_presence_inexact(): void
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

    public function test_and_of_translatable_is_exact(): void
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

    public function test_and_partial_translatable_is_inexact(): void
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

    public function test_and_with_no_translatable_children_returns_null(): void
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

    public function test_or_of_translatable_is_exact(): void
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

    public function test_or_with_one_untranslatable_child_returns_null(): void
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

    public function test_or_with_inexact_child_is_inexact(): void
    {
        $result = $this->subject->translate(new OrFilter(
            new AndFilter(
                new PresentFilter('cn'),
                new MatchingRuleFilter(
                    '1.2.840.113556.1.4.803',
                    'memberOf',
                    '2',
                ),
            ),
            new EqualityFilter(
                'sn',
                'Smith',
            ),
        ));

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_not_present_emits_plain_not(): void
    {
        $result = $this->subject->translate(
            new NotFilter(new PresentFilter('cn')),
        );

        self::assertNotNull($result);
        self::assertStringStartsWith(
            'NOT (lc_dn IN (',
            $result->sql,
        );
        self::assertTrue($result->isExact);
    }

    public function test_not_equality_emits_plain_not_for_the_evaluator_to_refine(): void
    {
        $result = $this->subject->translate(
            new NotFilter(new EqualityFilter(
                'cn',
                'Alice',
            )),
        );

        self::assertNotNull($result);
        self::assertStringStartsWith(
            'NOT (',
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
                new PresentFilter('cn'),
                new MatchingRuleFilter(
                    '1.2.840.113556.1.4.803',
                    'memberOf',
                    '2',
                ),
            )),
        );

        self::assertNotNull($result);
        self::assertFalse($result->isExact);
    }

    public function test_not_with_untranslatable_child_returns_null(): void
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

    public function test_equality_exposes_a_sidecar_condition(): void
    {
        $result = $this->subject->translate(new EqualityFilter('cn', 'alice'));

        self::assertNotNull($result);
        self::assertSame(
            "s.attr_name_lower = 'cn' AND s.value_lower = ?",
            $result->sidecarCondition,
        );
    }

    public function test_present_exposes_a_value_less_sidecar_condition(): void
    {
        $result = $this->subject->translate(new PresentFilter('cn'));

        self::assertNotNull($result);
        self::assertSame(
            "s.attr_name_lower = 'cn'",
            $result->sidecarCondition,
        );
    }

    public function test_prefix_substring_exposes_a_sidecar_condition(): void
    {
        $result = $this->subject->translate((new SubstringFilter('cn'))->setStartsWith('al'));

        self::assertNotNull($result);
        self::assertSame(
            "s.attr_name_lower = 'cn' AND s.value_lower LIKE ? ESCAPE '!'",
            $result->sidecarCondition,
        );
    }

    public function test_gte_exposes_a_sidecar_condition(): void
    {
        $result = $this->subject->translate(new GreaterThanOrEqualFilter('cn', 'a'));

        self::assertNotNull($result);
        self::assertSame(
            "s.attr_name_lower = 'cn' AND s.value_lower >= ?",
            $result->sidecarCondition,
        );
    }

    public function test_composed_and_leaves_the_sidecar_condition_null(): void
    {
        $result = $this->subject->translate(new AndFilter(
            new EqualityFilter('cn', 'alice'),
            new EqualityFilter('sn', 'smith'),
        ));

        self::assertNotNull($result);
        self::assertNull($result->sidecarCondition);
    }

    public function test_negation_leaves_the_sidecar_condition_null(): void
    {
        $result = $this->subject->translate(new NotFilter(new EqualityFilter('cn', 'alice')));

        self::assertNotNull($result);
        self::assertNull($result->sidecarCondition);
    }

    public function test_indexed_substring_leaves_the_sidecar_condition_null(): void
    {
        $translator = new SqliteFilterTranslator(
            $this->attributeContext(),
            new TrigramSubstringIndex(['cn']),
        );

        $result = $translator->translate((new SubstringFilter('cn'))->setContains('smith'));

        self::assertNotNull($result);
        self::assertNull($result->sidecarCondition);
    }

    public function test_composed_and_exposes_each_childs_drivable_leaf(): void
    {
        $result = $this->subject->translate(new AndFilter(
            new EqualityFilter('objectClass', 'person'),
            new EqualityFilter('cn', 'alice'),
        ));

        self::assertNotNull($result);
        self::assertCount(
            2,
            $result->drivableLeaves,
        );
        self::assertSame(
            "s.attr_name_lower = 'objectclass' AND s.value_lower = ?",
            $result->drivableLeaves[0]->condition,
        );
        self::assertSame(
            ['person'],
            $result->drivableLeaves[0]->params,
        );
        self::assertSame(
            ['alice'],
            $result->drivableLeaves[1]->params,
        );
    }

    public function test_nested_and_flattens_drivable_leaves(): void
    {
        $result = $this->subject->translate(new AndFilter(
            new AndFilter(
                new EqualityFilter('a', '1'),
                new EqualityFilter('b', '2'),
            ),
            new EqualityFilter('c', '3'),
        ));

        self::assertNotNull($result);
        self::assertCount(
            3,
            $result->drivableLeaves,
        );
    }

    public function test_or_exposes_no_drivable_leaves(): void
    {
        $result = $this->subject->translate(new OrFilter(
            new EqualityFilter('cn', 'a'),
            new EqualityFilter('cn', 'b'),
        ));

        self::assertNotNull($result);
        self::assertSame(
            [],
            $result->drivableLeaves,
        );
    }

    /**
     * The context is fixed at construction, so a test wanting different schema answers needs its own translator.
     */
    private function translateWith(
        FilterInterface $filter,
        AttributeContextInterface $context,
    ): ?SqlFilterResult {
        return (new SqliteFilterTranslator($context))->translate($filter);
    }

    private function attributeContext(
        ?bool $integerOrdered = null,
        AttributeFilterSupport $support = AttributeFilterSupport::Exact,
        bool $assertionConforms = true,
        bool $hasSubstringRule = true,
    ): AttributeContextInterface {
        $context = $this->createMock(AttributeContextInterface::class);
        $context->method('isIntegerOrdered')->willReturn($integerOrdered);
        $context->method('filterSupport')->willReturn($support);
        $context->method('assertionValueConforms')->willReturn($assertionConforms);
        $context->method('hasSubstringRule')->willReturn($hasSubstringRule);

        return $context;
    }
}
