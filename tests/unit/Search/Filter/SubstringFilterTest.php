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
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use PHPUnit\Framework\TestCase;

final class SubstringFilterTest extends TestCase
{
    private SubstringFilter $subject;

    protected function setUp(): void
    {
        $this->subject = new SubstringFilter(
            'foo',
            'f',
            'o',
            'o',
            'bar'
        );
    }

    public function test_it_should_get_the_starts_with_value(): void
    {
        self::assertEquals(
            'f',
            $this->subject->getStartsWith(),
        );

        $this->subject->setStartsWith(null);

        self::assertNull($this->subject->getStartsWith());
    }

    public function test_it_should_get_the_ends_with_value(): void
    {
        self::assertEquals(
            'o',
            $this->subject->getEndsWith(),
        );

        $this->subject->setEndsWith(null);

        self::assertNull($this->subject->getEndsWith());
    }

    public function test_it_should_get_the_contains_value(): void
    {
        self::assertSame(
            ['o', 'bar'],
            $this->subject->getContains(),
        );

        $this->subject->setContains();

        self::assertSame(
            [],
            $this->subject->getContains(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        self::assertEquals(
            Asn1::context(4, Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequenceOf(
                    Asn1::context(0, Asn1::octetString('f')),
                    Asn1::context(1, Asn1::octetString('o')),
                    Asn1::context(1, Asn1::octetString('bar')),
                    Asn1::context(2, Asn1::octetString('o'))
                )
            )),
            $this->subject->toAsn1(),
        );

        $this->subject->setStartsWith(null);
        self::assertEquals(
            Asn1::context(4, Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequenceOf(
                    Asn1::context(1, Asn1::octetString('o')),
                    Asn1::context(1, Asn1::octetString('bar')),
                    Asn1::context(2, Asn1::octetString('o'))
                )
            )),
            $this->subject->toAsn1(),
        );

        $this->subject->setEndsWith(null);
        self::assertEquals(
            Asn1::context(4, Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::sequenceOf(
                    Asn1::context(1, Asn1::octetString('o')),
                    Asn1::context(1, Asn1::octetString('bar'))
                )
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_error_if_no_starts_with_ends_with_or_contains_was_supplied(): void
    {
        self::expectException(RuntimeException::class);

        $this->subject->setStartsWith(null);
        $this->subject->setEndsWith(null);
        $this->subject->setContains();

        $this->subject->toAsn1();
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $substring = new SubstringFilter(
            'foo',
            'foo',
            'bar',
            'foobar',
            'wee',
        );
        self::assertEquals(
            $substring,
            SubstringFilter::fromAsn1($substring->toAsn1())
        );

        $substring = new SubstringFilter(
            'foo',
            'foo',
            'bar',
        );
        self::assertEquals(
            $substring,
            SubstringFilter::fromAsn1($substring->toAsn1())
        );

        $substring = new SubstringFilter(
            'foo',
            'foo',
        );
        self::assertEquals(
            $substring,
            SubstringFilter::fromAsn1($substring->toAsn1())
        );

        $substring = new SubstringFilter(
            'foo',
            null,
            'foo'
        );
        self::assertEquals(
            $substring,
            SubstringFilter::fromAsn1($substring->toAsn1())
        );

        $substring = new SubstringFilter(
            'foo',
            null,
            null,
            'foo',
            'bar'
        );
        self::assertEquals(
            $substring,
            SubstringFilter::fromAsn1($substring->toAsn1())
        );
    }

    public function test_it_should_get_the_string_filter_representation(): void
    {
        self::assertSame(
            '(foo=f*o*bar*o)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_get_the_filter_representation_with_a_starts_with(): void
    {
        $this->subject->setStartsWith('bar');
        $this->subject->setEndsWith(null);
        $this->subject->setContains();

        self::assertSame(
            '(foo=bar*)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_get_the_filter_representation_with_an_ends_with(): void
    {
        $this->subject->setStartsWith(null);
        $this->subject->setEndsWith('bar');
        $this->subject->setContains();

        self::assertSame(
            '(foo=*bar)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_get_a_filter_representation_with_a_start_and_end(): void
    {
        $this->subject->setStartsWith('foo');
        $this->subject->setEndsWith('bar');
        $this->subject->setContains();

        self::assertSame(
            '(foo=foo*bar)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_get_a_filter_representation_with_a_start_and_contains(): void
    {
        $this->subject->setStartsWith('foo');
        $this->subject->setEndsWith(null);
        $this->subject->setContains('b', 'a', 'r');

        self::assertSame(
            '(foo=foo*b*a*r*)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_get_a_filter_representation_with_an_end_and_contains(): void
    {
        $this->subject->setStartsWith(null);
        $this->subject->setEndsWith('foo');
        $this->subject->setContains('b', 'a', 'r');

        self::assertSame(
            '(foo=*b*a*r*foo)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_have_a_filter_as_a_toString_representation(): void
    {
        self::assertSame(
            '(foo=f*o*bar*o)',
            (string) $this->subject,
        );
    }

    public function test_it_should_escape_values_on_the_string_representation(): void
    {
        $this->subject = new SubstringFilter('foo', ')(bar=*5');
        $this->subject->setStartsWith('*');
        $this->subject->setEndsWith(')(o=*');
        $this->subject->setContains('fo*');

        self::assertSame(
            '(foo=\2a*fo\2a*\29\28o=\2a)',
            $this->subject->toString(),
        );
    }
}
