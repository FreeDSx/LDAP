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

namespace Tests\Unit\FreeDSx\Ldap\Search\Filter;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use PHPUnit\Framework\TestCase;

final class MatchingRuleFilterTest extends TestCase
{
    private MatchingRuleFilter $subject;

    protected function setUp(): void
    {
        $this->subject = new MatchingRuleFilter(
            'foo',
            'bar',
            'foobar',
        );
    }

    public function test_it_should_get_the_attribute_name(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getAttribute(),
        );
    }

    public function test_it_should_get_the_value(): void
    {
        self::assertSame(
            'foobar',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_not_use_dn_attributes_by_default(): void
    {
        self::assertFalse($this->subject->getUseDnAttributes());
    }

    public function test_it_should_set_whether_to_use_dn_attributes_by_default(): void
    {
        $this->subject->setUseDnAttributes(true);

        self::assertTrue($this->subject->getUseDnAttributes());
    }

    public function test_it_should_set_the_matching_rule(): void
    {
        $this->subject->setMatchingRule('bleep');

        self::assertSame(
            'bleep',
            $this->subject->getMatchingRule(),
        );
    }

    public function test_it_should_be_able_to_set_the_attribute_to_null(): void
    {
        $this->subject->setAttribute(null);

        self::assertNull($this->subject->getAttribute());
    }

    public function test_it_should_be_able_to_set_the_matching_rule_to_null(): void
    {
        $this->subject->setMatchingRule(null);

        self::assertNull($this->subject->getMatchingRule());
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::context(9, Asn1::sequence(
                Asn1::context(1, Asn1::octetString('foo')),
                Asn1::context(2, Asn1::octetString('bar')),
                Asn1::context(3, Asn1::octetString('foobar')),
                Asn1::context(4, Asn1::boolean(false)),
            )),
            $this->subject->toAsn1(),
        );

        $this->subject->setUseDnAttributes(true);
        self::assertEquals(
            Asn1::context(9, Asn1::sequence(
                Asn1::context(1, Asn1::octetString('foo')),
                Asn1::context(2, Asn1::octetString('bar')),
                Asn1::context(3, Asn1::octetString('foobar')),
                Asn1::context(4, Asn1::boolean(true)),
            )),
            $this->subject->toAsn1(),
        );

        $this->subject->setMatchingRule(null);
        self::assertEquals(
            Asn1::context(9, Asn1::sequence(
                Asn1::context(2, Asn1::octetString('bar')),
                Asn1::context(3, Asn1::octetString('foobar')),
                Asn1::context(4, Asn1::boolean(true))
            )),
            $this->subject->toAsn1(),
        );


        $this->subject->setAttribute(null);
        self::assertEquals(
            Asn1::context(9, Asn1::sequence(
                Asn1::context(3, Asn1::octetString('foobar')),
                Asn1::context(4, Asn1::boolean(true))
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $rule = new MatchingRuleFilter('foo', 'foo', 'bar', true);

        self::assertEquals(
            $rule,
            MatchingRuleFilter::fromAsn1($rule->toAsn1()),
        );
    }

    public function test_it_should_get_the_string_filter_representation(): void
    {
        self::assertSame(
            '(bar:foo:=foobar)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_get_the_filter_representation_with_a_dn_match(): void
    {
        $this->subject->setUseDnAttributes(true);

        self::assertSame(
            '(bar:foo:dn:=foobar)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_have_a_filter_as_a_toString_representation(): void
    {
        self::assertSame(
            '(bar:foo:=foobar)',
            (string) $this->subject,
        );
    }

    public function test_it_should_escape_values_on_the_string_representation(): void
    {
        $this->subject = new MatchingRuleFilter(
            'foo', 'bar',
            ')(bar=*5',
        );

        self::assertSame(
            '(bar:foo:=\29\28bar=\2a5)',
            $this->subject->toString(),
        );
    }
}
