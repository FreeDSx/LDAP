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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;

final class AndFilterTest extends TestCase
{
    private AndFilter $subject;

    protected function setUp(): void
    {
        $this->subject = new AndFilter(
            Filters::equal('foo', 'bar'),
            Filters::gte('foo', '2'),
        );
    }

    public function test_it_should_get_the_filters_it_contains(): void
    {
        self::assertEquals(
            [
                Filters::equal('foo', 'bar'),
                Filters::gte('foo', '2'),
            ],
            $this->subject->get(),
        );
    }

    public function test_it_should_set_the_filters(): void
    {
        $this->subject->set(Filters::equal('bar', 'foo'));

        self::assertEquals(
            [Filters::equal('bar', 'foo')],
            $this->subject->get(),
        );
    }

    public function test_it_should_add_to_the_filters(): void
    {
        $filter = Filters::equal('foobar', 'foobar');

        $this->subject->add($filter);

        self::assertContains(
            $filter,
            $this->subject->get(),
        );
    }

    public function test_it_should_remove_from_the_filters(): void
    {
        $filter = Filters::equal('foobar', 'foobar');

        $this->subject->add($filter);

        self::assertContains(
            $filter,
            $this->subject->get(),
        );

        $this->subject->remove($filter);

        self::assertNotContains(
            $filter,
            $this->subject->get(),
        );
    }

    public function test_it_should_check_if_a_filter_exists(): void
    {
        $filter = Filters::equal('foobar', 'foobar');

        self::assertFalse($this->subject->has($filter));

        $this->subject->add($filter);

        self::assertTrue($this->subject->has($filter));
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::context(0, Asn1::setOf(
                Filters::equal('foo', 'bar')->toAsn1(),
                Filters::gte('foo', '2')->toAsn1()
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $and = new AndFilter(new EqualityFilter('foo', 'bar'), new SubstringFilter('bar', 'foo'));

        self::assertEquals(
            $and,
            AndFilter::fromAsn1($and->toAsn1())
        );
    }

    /**
     * @dataProvider malformedAsn1DataProvider
     */
    public function test_it_should_not_be_constructed_from_invalid_asn1(AbstractType $type): void
    {
        self::expectException(ProtocolException::class);

        AndFilter::fromAsn1($type);
    }

    public function test_it_should_get_the_string_filter_representation(): void
    {
        self::assertSame(
            '(&(foo=bar)(foo>=2))',
            $this->subject->toString(),
        );
    }

    public function test_it_should_get_the_string_filter_representation_with_nested_containers(): void
    {
        $this->subject->add(Filters::or(Filters::equal('foo', 'bar')));

        self::assertSame(
            '(&(foo=bar)(foo>=2)(|(foo=bar)))',
            $this->subject->toString(),
        );
    }

    public function test_it_should_have_a_filter_as_a_toString_representation(): void
    {
        self::assertSame(
            '(&(foo=bar)(foo>=2))',
            (string) $this->subject,
        );
    }

    public function test_it_should_get_the_count(): void
    {
        self::assertCount(
            2,
            $this->subject,
        );
    }

    /**
     * @return array<array{AbstractType}>
     */
    public static function malformedAsn1DataProvider(): array
    {
        return [
            [Asn1::octetString('foo')],
            [Asn1::sequence()],
        ];
    }
}
