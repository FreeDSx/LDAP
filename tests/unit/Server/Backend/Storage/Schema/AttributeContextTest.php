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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Schema;

use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\AttributeFilterSupport;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeContext;
use PHPUnit\Framework\TestCase;

final class AttributeContextTest extends TestCase
{
    private Schema $schema;

    private AttributeContext $subject;

    protected function setUp(): void
    {
        $this->schema = SchemaResource::Core->load();
        $this->subject = new AttributeContext(
            $this->schema,
            new AttributeSyntaxResolver($this->schema),
        );
    }

    public function test_a_value_matching_the_syntax_conforms(): void
    {
        self::assertTrue($this->subject->assertionValueConforms('supportedLDAPVersion', '3'));
    }

    public function test_a_value_the_syntax_rejects_does_not_conform(): void
    {
        self::assertFalse($this->subject->assertionValueConforms('supportedLDAPVersion', 'abc'));
    }

    public function test_a_type_declaring_a_substring_rule_has_one(): void
    {
        self::assertTrue($this->subject->hasSubstringRule('cn'));
    }

    public function test_options_are_dropped_before_resolving_the_substring_rule(): void
    {
        self::assertTrue($this->subject->hasSubstringRule('cn;lang-en'));
    }

    public function test_a_type_declaring_no_substring_rule_has_none(): void
    {
        self::assertFalse($this->subject->hasSubstringRule('supportedLDAPVersion'));
    }

    public function test_has_subordinates_is_answerable_in_sql_despite_being_derived(): void
    {
        self::assertSame(
            AttributeFilterSupport::Exact,
            $this->subject->filterSupport('hasSubordinates'),
        );
    }

    public function test_a_derived_attribute_with_no_stored_rows_needs_the_evaluator(): void
    {
        self::assertSame(
            AttributeFilterSupport::NeedsEvaluator,
            $this->subject->filterSupport('entryDN'),
        );
    }

    public function test_a_type_the_schema_does_not_define_can_never_match(): void
    {
        self::assertSame(
            AttributeFilterSupport::NeverMatches,
            $this->subject->filterSupport('shoeSize'),
        );
    }

    public function test_a_type_with_subtypes_needs_the_evaluator(): void
    {
        self::assertSame(
            AttributeFilterSupport::NeedsEvaluator,
            $this->subject->filterSupport('name'),
        );
    }

    public function test_a_type_without_subtypes_is_answerable_in_sql(): void
    {
        self::assertSame(
            AttributeFilterSupport::Exact,
            $this->subject->filterSupport('cn'),
        );
    }

    public function test_options_are_dropped_before_resolving_filter_support(): void
    {
        self::assertSame(
            AttributeFilterSupport::Exact,
            $this->subject->filterSupport('cn;lang-en'),
        );
    }

    public function test_an_integer_ordered_type_is_reported_as_such(): void
    {
        self::assertTrue($this->subject->isIntegerOrdered('supportedLDAPVersion'));
    }

    public function test_a_string_ordered_type_is_not_integer_ordered(): void
    {
        self::assertFalse($this->subject->isIntegerOrdered('cn'));
    }

    public function test_an_unresolved_type_has_no_ordering_answer(): void
    {
        self::assertNull($this->subject->isIntegerOrdered('shoeSize'));
    }

    public function test_a_case_insensitively_matched_type_is_reported_as_such(): void
    {
        self::assertTrue($this->subject->isCaseInsensitive('cn'));
    }

    public function test_a_case_sensitively_matched_type_is_reported_as_such(): void
    {
        self::assertFalse($this->subject->isCaseInsensitive('createTimestamp'));
    }

    public function test_an_unresolved_type_has_no_case_answer(): void
    {
        self::assertNull($this->subject->isCaseInsensitive('shoeSize'));
    }
}
