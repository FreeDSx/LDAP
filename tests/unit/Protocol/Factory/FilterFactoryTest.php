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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Factory;

use Closure;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\FilterDepthExceededException;
use FreeDSx\Ldap\Exception\FilterTooWideException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\FilterFactory;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class FilterFactoryTest extends TestCase
{
    /**
     * @return iterable<string, array{Closure(FilterInterface): FilterInterface}>
     */
    public static function nestingFilterProvider(): iterable
    {
        yield 'not' => [static fn(FilterInterface $filter): FilterInterface => Filters::not($filter)];
        yield 'and' => [static fn(FilterInterface $filter): FilterInterface => Filters::and($filter)];
        yield 'or' => [static fn(FilterInterface $filter): FilterInterface => Filters::or($filter)];
    }

    /**
     * @param Closure(FilterInterface): FilterInterface $nest
     */
    #[DataProvider('nestingFilterProvider')]
    public function test_it_decodes_a_filter_nested_to_the_maximum_depth(Closure $nest): void
    {
        $filter = self::nestedFilter(
            $nest,
            FilterFactory::MAX_NESTING_DEPTH,
        );

        self::assertEquals(
            $filter,
            FilterFactory::get(self::receivedAsn1($filter)),
        );
    }

    /**
     * @param Closure(FilterInterface): FilterInterface $nest
     */
    #[DataProvider('nestingFilterProvider')]
    public function test_it_refuses_a_filter_nested_past_the_maximum_depth_as_unwilling_to_perform(Closure $nest): void
    {
        $filter = self::nestedFilter(
            $nest,
            FilterFactory::MAX_NESTING_DEPTH + 1,
        );

        $this->expectException(FilterDepthExceededException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        FilterFactory::get(self::receivedAsn1($filter));
    }

    public function test_it_decodes_a_filter_holding_the_maximum_items(): void
    {
        $filter = Filters::or(...self::equalities(FilterFactory::MAX_ITEMS));

        self::assertEquals(
            $filter,
            FilterFactory::get(self::receivedAsn1($filter)),
        );
    }

    public function test_it_refuses_a_filter_holding_more_than_the_maximum_items_as_an_administrative_limit(): void
    {
        $filter = Filters::or(...self::equalities(FilterFactory::MAX_ITEMS + 1));

        $this->expectException(FilterTooWideException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        FilterFactory::get(self::receivedAsn1($filter));
    }

    public function test_it_counts_the_items_of_every_nested_filter_together(): void
    {
        $half = intdiv(
            FilterFactory::MAX_ITEMS,
            2,
        );
        $filter = Filters::and(
            Filters::or(...self::equalities($half)),
            Filters::not(Filters::or(...self::equalities($half + 1))),
        );

        $this->expectException(FilterTooWideException::class);

        FilterFactory::get(self::receivedAsn1($filter));
    }

    /**
     * @return iterable<string, array{Closure(): FilterInterface}>
     */
    public static function emptySetProvider(): iterable
    {
        yield 'empty and' => [
            static fn(): FilterInterface => Filters::and(),
        ];
        yield 'empty or' => [
            static fn(): FilterInterface => Filters::or(),
        ];
        yield 'negated empty and' => [
            static fn(): FilterInterface => Filters::not(Filters::and()),
        ];
    }

    /**
     * @param Closure(): FilterInterface $emptySet
     */
    #[DataProvider('emptySetProvider')]
    public function test_it_counts_each_empty_set_as_an_item(Closure $emptySet): void
    {
        $filter = Filters::or(...array_map(
            static fn(): FilterInterface => $emptySet(),
            range(
                0,
                FilterFactory::MAX_ITEMS,
            ),
        ));

        $this->expectException(FilterTooWideException::class);

        FilterFactory::get(self::receivedAsn1($filter));
    }

    public function test_it_decodes_empty_sets_that_reach_the_maximum_items(): void
    {
        $filter = Filters::or(...array_map(
            static fn(): FilterInterface => Filters::and(),
            range(
                1,
                FilterFactory::MAX_ITEMS,
            ),
        ));

        self::assertEquals(
            $filter,
            FilterFactory::get(self::receivedAsn1($filter)),
        );
    }

    public function test_it_counts_each_part_of_a_substring_item(): void
    {
        $filter = Filters::or(
            Filters::substring(
                'cn',
                'a',
                'z',
                'm',
            ),
            ...self::equalities(FilterFactory::MAX_ITEMS - 2),
        );

        $this->expectException(FilterTooWideException::class);

        FilterFactory::get(self::receivedAsn1($filter));
    }

    public function test_it_decodes_a_substring_item_whose_parts_reach_the_maximum_items(): void
    {
        $filter = Filters::or(
            Filters::substring(
                'cn',
                'a',
                'z',
            ),
            ...self::equalities(FilterFactory::MAX_ITEMS - 2),
        );

        self::assertEquals(
            $filter,
            FilterFactory::get(self::receivedAsn1($filter)),
        );
    }

    public function test_it_should_check_if_a_mapping_exists(): void
    {
        self::assertTrue(FilterFactory::has(0));
        self::assertFalse(FilterFactory::has(99));
    }

    public function test_it_should_set_a_mapping(): void
    {
        FilterFactory::set(99, EqualityFilter::class);

        self::assertTrue(FilterFactory::has(99));
    }

    public function test_it_should_get_a_mapping(): void
    {
        self::assertEquals(
            new EqualityFilter('foo', 'bar'),
            FilterFactory::get((new EqualityFilter('foo', 'bar'))->toAsn1()),
        );
    }

    /**
     * @param Closure(FilterInterface): FilterInterface $nest
     */
    private static function nestedFilter(
        Closure $nest,
        int $depth,
    ): FilterInterface {
        $filter = Filters::equal(
            'cn',
            'foo',
        );
        for ($i = 0; $i < $depth; $i++) {
            $filter = $nest($filter);
        }

        return $filter;
    }

    /**
     * @return list<EqualityFilter>
     */
    private static function equalities(int $count): array
    {
        return array_map(
            static fn(int $i): EqualityFilter => new EqualityFilter(
                'cn',
                "v{$i}",
            ),
            range(
                1,
                $count,
            ),
        );
    }

    /**
     * @return AbstractType<mixed>
     */
    private static function receivedAsn1(FilterInterface $filter): AbstractType
    {
        $encoder = new LdapEncoder();

        return $encoder->decode($encoder->encode($filter->toAsn1()));
    }
}
