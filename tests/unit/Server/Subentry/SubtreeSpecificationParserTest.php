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

namespace Tests\Unit\FreeDSx\Ldap\Server\Subentry;

use FreeDSx\Ldap\Exception\SubtreeSpecificationParseException;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Server\Subentry\SubtreeSpecificationParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SubtreeSpecificationParserTest extends TestCase
{
    private SubtreeSpecificationParser $subject;

    protected function setUp(): void
    {
        $this->subject = new SubtreeSpecificationParser();
    }

    public function test_an_empty_specification_covers_the_whole_subtree(): void
    {
        $parsed = $this->subject->parse('{ }');

        self::assertSame(
            '',
            $parsed->base->toString(),
        );
        self::assertSame(
            [],
            $parsed->chopBefore,
        );
        self::assertSame(
            [],
            $parsed->chopAfter,
        );
        self::assertSame(
            0,
            $parsed->minimum,
        );
        self::assertNull($parsed->maximum);
        self::assertNull($parsed->specificationFilter);
    }

    public function test_it_reads_a_base(): void
    {
        $parsed = $this->subject->parse('{ base "ou=people" }');

        self::assertSame(
            'ou=people',
            $parsed->base->toString(),
        );
    }

    public function test_it_reads_the_depth_bounds(): void
    {
        $parsed = $this->subject->parse('{ minimum 1, maximum 3 }');

        self::assertSame(
            1,
            $parsed->minimum,
        );
        self::assertSame(
            3,
            $parsed->maximum,
        );
    }

    public function test_it_reads_both_kinds_of_chop_point(): void
    {
        $parsed = $this->subject->parse(
            '{ specificExclusions { chopBefore:"cn=x", chopAfter:"ou=y", chopBefore:"cn=z" } }',
        );

        self::assertSame(
            ['cn=x', 'cn=z'],
            array_map(strval(...), $parsed->chopBefore),
        );
        self::assertSame(
            ['ou=y'],
            array_map(strval(...), $parsed->chopAfter),
        );
    }

    public function test_an_item_refinement_asserts_an_object_class(): void
    {
        $parsed = $this->subject->parse('{ specificationFilter item:person }');

        $filter = $parsed->specificationFilter;
        self::assertInstanceOf(
            EqualityFilter::class,
            $filter,
        );
        self::assertSame(
            'objectClass',
            $filter->getAttribute(),
        );
        self::assertSame(
            'person',
            $filter->getValue(),
        );
    }

    public function test_a_nested_refinement_maps_onto_the_filter_types(): void
    {
        $parsed = $this->subject->parse(
            '{ specificationFilter and:{ item:person, not:item:organizationalPerson, or:{ item:a, item:b } } }',
        );

        $filter = $parsed->specificationFilter;
        self::assertInstanceOf(
            AndFilter::class,
            $filter,
        );

        $children = $filter->get();
        self::assertCount(
            3,
            $children,
        );
        self::assertInstanceOf(
            EqualityFilter::class,
            $children[0],
        );
        self::assertInstanceOf(
            NotFilter::class,
            $children[1],
        );
        self::assertInstanceOf(
            OrFilter::class,
            $children[2],
        );
    }

    public function test_an_empty_refinement_set_is_accepted(): void
    {
        $parsed = $this->subject->parse('{ specificationFilter and:{ } }');

        self::assertInstanceOf(
            AndFilter::class,
            $parsed->specificationFilter,
        );
    }

    public function test_a_doubled_quote_stands_for_one_literal_quote(): void
    {
        $parsed = $this->subject->parse('{ base "cn=a""b" }');

        self::assertSame(
            'cn=a"b',
            $parsed->base->toString(),
        );
    }

    public function test_it_tolerates_absent_whitespace(): void
    {
        $parsed = $this->subject->parse('{base "ou=people",minimum 1}');

        self::assertSame(
            'ou=people',
            $parsed->base->toString(),
        );
        self::assertSame(
            1,
            $parsed->minimum,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function roundTripProvider(): iterable
    {
        yield 'empty' => ['{ }'];
        yield 'base' => ['{ base "ou=people" }'];
        yield 'minimum' => ['{ minimum 2 }'];
        yield 'maximum' => ['{ maximum 5 }'];
        yield 'depth range' => ['{ base "ou=people", minimum 1, maximum 3 }'];
        yield 'chop before' => ['{ specificExclusions { chopBefore:"cn=x" } }'];
        yield 'chop after' => ['{ specificExclusions { chopAfter:"ou=y" } }'];
        yield 'both chops' => ['{ specificExclusions { chopBefore:"cn=x", chopAfter:"ou=y" } }'];
        yield 'item refinement' => ['{ specificationFilter item:person }'];
        yield 'not refinement' => ['{ specificationFilter not:item:person }'];
        yield 'and refinement' => ['{ specificationFilter and:{ item:a, item:b } }'];
        yield 'or refinement' => ['{ specificationFilter or:{ item:a, item:b } }'];
        yield 'nested refinement' => ['{ specificationFilter and:{ item:a, not:or:{ item:b, item:c } } }'];
        yield 'embedded quote' => ['{ base "cn=a""b" }'];
        yield 'every component' => [
            '{ base "ou=people", specificExclusions { chopBefore:"cn=x", chopAfter:"ou=y" }, '
            . 'minimum 1, maximum 4, specificationFilter and:{ item:person, not:item:device } }',
        ];
    }

    #[DataProvider('roundTripProvider')]
    public function test_it_round_trips(string $specification): void
    {
        self::assertSame(
            $specification,
            $this->subject->parse($specification)->toString(),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedProvider(): iterable
    {
        yield 'empty string' => [''];
        yield 'no braces' => ['base "ou=people"'];
        yield 'unterminated' => ['{ base "ou=people"'];
        yield 'unterminated string' => ['{ base "ou=people }'];
        yield 'unquoted base' => ['{ base ou=people }'];
        yield 'unknown component' => ['{ nonsense "ou=people" }'];
        yield 'unknown exclusion' => ['{ specificExclusions { chopSideways:"cn=x" } }'];
        yield 'unknown refinement' => ['{ specificationFilter maybe:person }'];
        yield 'negative minimum' => ['{ minimum -1 }'];
        yield 'non numeric minimum' => ['{ minimum many }'];
        yield 'maximum below minimum' => ['{ minimum 3, maximum 1 }'];
        yield 'duplicate component' => ['{ base "ou=a", base "ou=b" }'];
        yield 'trailing content' => ['{ } trailing'];
        yield 'missing refinement colon' => ['{ specificationFilter item person }'];
        yield 'unterminated refinement set' => ['{ specificationFilter and:{ item:a }'];
    }

    #[DataProvider('malformedProvider')]
    public function test_it_rejects_malformed_input(string $specification): void
    {
        $this->expectException(SubtreeSpecificationParseException::class);

        $this->subject->parse($specification);
    }

    public function test_a_failure_carries_the_source_and_offset(): void
    {
        try {
            $this->subject->parse('{ base "ou=people", nonsense 1 }');

            self::fail('Expected a parse failure.');
        } catch (SubtreeSpecificationParseException $exception) {
            self::assertSame(
                '{ base "ou=people", nonsense 1 }',
                $exception->getSpecification(),
            );
            self::assertSame(
                20,
                $exception->getOffset(),
            );
        }
    }
}
