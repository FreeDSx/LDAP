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
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;

final class NotFilterTest extends TestCase
{
    private NotFilter $subject;

    protected function setUp(): void
    {
        $this->subject = new NotFilter(Filters::equal(
            attribute: 'foo',
            value: 'bar',
        ));
    }

    public function test_it_should_set_the_filter(): void
    {

        $this->subject->set(Filters::gte(
            'foobar',
            'foo',
        ));

        self::assertEquals(
            Filters::gte('foobar', 'foo'),
            $this->subject->get(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::context(2, Asn1::sequence(
                Filters::equal('foo', 'bar')->toAsn1(),
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        self::assertEquals(
            new NotFilter(new EqualityFilter('foo', 'bar')),
            NotFilter::fromAsn1(
                (new NotFilter(Filters::equal('foo', 'bar')))->toAsn1(),
            ),
        );
    }

    public function test_it_should_get_the_string_filter_representation(): void
    {
        self::assertSame(
            '(!(foo=bar))',
            $this->subject->toString(),
        );
    }

    public function test_it_should_have_a_filter_as_a_toString_representation(): void
    {
        self::assertSame(
            '(!(foo=bar))',
            (string) $this->subject,
        );
    }

    public function test_it_should_escape_values_on_the_string_representation(): void
    {
        $this->subject = new NotFilter(Filters::equal('foo', '*bar'));

        self::assertSame(
            '(!(foo=\2abar))',
            $this->subject->toString(),
        );
    }
}
