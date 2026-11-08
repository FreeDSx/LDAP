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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Filter;

use Closure;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\FilterDepthExceededException;
use FreeDSx\Ldap\Exception\FilterTooWideException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ReceivedAsn1Trait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

use function array_map;
use function intdiv;
use function range;

final class FilterDecoderTest extends TestCase
{
    use ReceivedAsn1Trait;
    use ServerContainerTrait;

    private FilterDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(FilterDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    #[DataProvider('filters')]
    public function testItDecodesEachKindOfFilter(FilterInterface $filter): void
    {
        self::assertEquals(
            $filter,
            $this->decode($filter),
        );
    }

    /**
     * @return iterable<string, array{FilterInterface}>
     */
    public static function filters(): iterable
    {
        yield 'and' => [Filters::and(
            Filters::equal(
                'cn',
                'foo',
            ),
            Filters::present('sn'),
        )];
        yield 'or' => [Filters::or(
            Filters::equal(
                'cn',
                'foo',
            ),
            Filters::present('sn'),
        )];
        yield 'not' => [Filters::not(Filters::present('cn'))];
        yield 'equality' => [Filters::equal(
            'cn',
            'foo',
        )];
        yield 'substring' => [Filters::substring(
            'cn',
            'a',
            'z',
            'm',
        )];
        yield 'greater or equal' => [Filters::greaterThanOrEqual(
            'uidNumber',
            '10',
        )];
        yield 'less or equal' => [Filters::lessThanOrEqual(
            'uidNumber',
            '10',
        )];
        yield 'present' => [Filters::present('cn')];
        yield 'approximate' => [Filters::approximate(
            'cn',
            'foo',
        )];
        yield 'extensible match' => [Filters::extensible(
            'cn',
            'foo',
            '2.5.13.2',
            true,
        )];
    }

    public function testItRefusesAFilterItDoesNotRecognize(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The received filter "10" is not recognized.');

        $this->subject->decode(
            Asn1::context(
                10,
                Asn1::octetString('foo'),
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{Closure(FilterInterface): FilterInterface}>
     */
    public static function nestingFilters(): iterable
    {
        yield 'not' => [static fn(FilterInterface $filter): FilterInterface => Filters::not($filter)];
        yield 'and' => [static fn(FilterInterface $filter): FilterInterface => Filters::and($filter)];
        yield 'or' => [static fn(FilterInterface $filter): FilterInterface => Filters::or($filter)];
    }

    /**
     * @param Closure(FilterInterface): FilterInterface $nest
     */
    #[DataProvider('nestingFilters')]
    public function testItDecodesAFilterNestedToTheMaximumDepth(Closure $nest): void
    {
        $filter = self::nestedFilter(
            $nest,
            FilterDecoder::MAX_NESTING_DEPTH,
        );

        self::assertEquals(
            $filter,
            $this->decode($filter),
        );
    }

    /**
     * @param Closure(FilterInterface): FilterInterface $nest
     */
    #[DataProvider('nestingFilters')]
    public function testItRefusesAFilterNestedPastTheMaximumDepthAsUnwillingToPerform(Closure $nest): void
    {
        $this->expectException(FilterDepthExceededException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->decode(self::nestedFilter(
            $nest,
            FilterDecoder::MAX_NESTING_DEPTH + 1,
        ));
    }

    public function testItDecodesAFilterHoldingTheMaximumItems(): void
    {
        $filter = Filters::or(...self::equalities(FilterDecoder::MAX_ITEMS));

        self::assertEquals(
            $filter,
            $this->decode($filter),
        );
    }

    public function testItRefusesAFilterHoldingMoreThanTheMaximumItemsAsAnAdministrativeLimit(): void
    {
        $this->expectException(FilterTooWideException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->decode(Filters::or(...self::equalities(FilterDecoder::MAX_ITEMS + 1)));
    }

    public function testItCountsTheItemsOfEveryNestedFilterTogether(): void
    {
        $half = intdiv(
            FilterDecoder::MAX_ITEMS,
            2,
        );

        $this->expectException(FilterTooWideException::class);

        $this->decode(Filters::and(
            Filters::or(...self::equalities($half)),
            Filters::not(Filters::or(...self::equalities($half + 1))),
        ));
    }

    public function testItCountsEachFilterItDecodesOnItsOwn(): void
    {
        $filter = Filters::or(...self::equalities(FilterDecoder::MAX_ITEMS));
        $this->decode($filter);

        self::assertEquals(
            $filter,
            $this->decode($filter),
        );
    }

    /**
     * @return iterable<string, array{Closure(): FilterInterface}>
     */
    public static function emptySets(): iterable
    {
        yield 'empty and' => [static fn(): FilterInterface => Filters::and()];
        yield 'empty or' => [static fn(): FilterInterface => Filters::or()];
        yield 'negated empty and' => [static fn(): FilterInterface => Filters::not(Filters::and())];
    }

    /**
     * @param Closure(): FilterInterface $emptySet
     */
    #[DataProvider('emptySets')]
    public function testItCountsEachEmptySetAsAnItem(Closure $emptySet): void
    {
        $this->expectException(FilterTooWideException::class);

        $this->decode(Filters::or(...array_map(
            static fn(): FilterInterface => $emptySet(),
            range(
                0,
                FilterDecoder::MAX_ITEMS,
            ),
        )));
    }

    public function testItDecodesEmptySetsThatReachTheMaximumItems(): void
    {
        $filter = Filters::or(...array_map(
            static fn(): FilterInterface => Filters::and(),
            range(
                1,
                FilterDecoder::MAX_ITEMS,
            ),
        ));

        self::assertEquals(
            $filter,
            $this->decode($filter),
        );
    }

    public function testItCountsEachPartOfASubstringItem(): void
    {
        $this->expectException(FilterTooWideException::class);

        $this->decode(Filters::or(
            Filters::substring(
                'cn',
                'a',
                'z',
                'm',
            ),
            ...self::equalities(FilterDecoder::MAX_ITEMS - 2),
        ));
    }

    public function testItDecodesASubstringItemWhosePartsReachTheMaximumItems(): void
    {
        $filter = Filters::or(
            Filters::substring(
                'cn',
                'a',
                'z',
            ),
            ...self::equalities(FilterDecoder::MAX_ITEMS - 2),
        );

        self::assertEquals(
            $filter,
            $this->decode($filter),
        );
    }

    private function decode(FilterInterface $filter): FilterInterface
    {
        return $this->subject->decode(
            self::received($filter->toAsn1()),
            $this->context,
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
}
