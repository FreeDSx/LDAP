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
use FreeDSx\Ldap\Exception\FilterParseException;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class EqualityFilterTest extends TestCase
{
    private EqualityFilter $subject;

    protected function setUp(): void
    {
        $this->subject = new EqualityFilter(
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

        $this->subject->setAttribute('foobar');

        self::assertSame(
            'foobar',
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
            Asn1::context(3, Asn1::sequence(
                Asn1::octetString('foo'),
                Asn1::octetString('bar'),
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        self::assertEquals(
            new EqualityFilter('foo', 'bar'),
            EqualityFilter::fromAsn1((new EqualityFilter('foo', 'bar'))->toAsn1()),
        );
    }

    public function test_it_should_get_the_string_filter_representation(): void
    {
        self::assertSame(
            '(foo=bar)',
            $this->subject->toString(),
        );
    }

    public function test_it_should_have_a_filter_as_a_toString_representation(): void
    {
        self::assertSame(
            '(foo=bar)',
            (string) $this->subject,
        );
    }

    public function test_it_should_escape_values_on_the_string_representation(): void
    {
        $this->subject = new EqualityFilter('foo', ')(bar=foo');

        self::assertSame(
            '(foo=\29\28bar=foo)',
            $this->subject->toString(),
        );
    }

    /**
     * @param non-empty-string $attribute
     */
    #[DataProvider('unrepresentableAttributeProvider')]
    public function test_an_attribute_outside_the_grammar_has_no_string_representation(string $attribute): void
    {
        self::expectException(FilterParseException::class);

        (new EqualityFilter($attribute, 'x'))->toString();
    }

    /**
     * RFC 4515 3 takes attr from RFC 4512 2.5, and nothing escapes an attribute into shape.
     *
     * @return iterable<string, array{non-empty-string}>
     */
    public static function unrepresentableAttributeProvider(): iterable
    {
        yield 'an opening parenthesis' => [
            'cn(bad',
        ];
        yield 'a closing parenthesis' => [
            'cn)bad',
        ];
        yield 'an equals sign' => [
            'cn=bad',
        ];
        yield 'an asterisk' => [
            'cn*bad',
        ];
        yield 'a leading digit' => [
            '1cn',
        ];
        yield 'an underscore' => [
            'user_id',
        ];
    }

    /**
     * @param non-empty-string $attribute
     */
    #[DataProvider('representableAttributeProvider')]
    public function test_an_attribute_within_the_grammar_is_emitted_as_written(string $attribute): void
    {
        self::assertSame(
            "($attribute=x)",
            (new EqualityFilter($attribute, 'x'))->toString(),
        );
    }

    /**
     * @return iterable<string, array{non-empty-string}>
     */
    public static function representableAttributeProvider(): iterable
    {
        yield 'a descr' => [
            'cn',
        ];
        yield 'a descr with hyphens and digits' => [
            'x-my-attr2',
        ];
        yield 'a numeric oid' => [
            '2.5.4.3',
        ];
        yield 'a descr carrying an option' => [
            'cn;lang-en',
        ];
    }
}
