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
     * @return AbstractType<mixed>
     */
    private static function receivedAsn1(FilterInterface $filter): AbstractType
    {
        $encoder = new LdapEncoder();

        return $encoder->decode($encoder->encode($filter->toAsn1()));
    }
}
