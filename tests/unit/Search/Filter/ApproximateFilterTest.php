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
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use PHPUnit\Framework\TestCase;

final class ApproximateFilterTest extends TestCase
{
    private ApproximateFilter $subject;

    protected function setUp(): void
    {
        $this->subject = new ApproximateFilter(
            'foo',
            'bar',
        );
    }

    public function test_it_should_get_the_attribute_name(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getAttribute(),
        );
    }

    public function test_it_should_get_the_value(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getValue(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::context(8, Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::octetString('bar')
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        self::assertEquals(
            new ApproximateFilter('foo', 'bar'),
            ApproximateFilter::fromAsn1((new ApproximateFilter('foo', 'bar'))->toAsn1())
        );
    }

    public function test_it_should_get_the_string_filter_representation(): void
    {
        self::assertSame(
            '(foo~=bar)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_have_a_filter_as_a_toString_representation(): void
    {
        self::assertSame(
            '(foo~=bar)',
            (string) $this->subject,
        );
    }

    public function test_it_should_escape_values_on_the_string_representation(): void
    {
        $this->subject = new ApproximateFilter('foo', ')(bar=foo');

        self::assertSame(
            '(foo~=\29\28bar=foo)',
            $this->subject->toString(),
        );
    }
}
