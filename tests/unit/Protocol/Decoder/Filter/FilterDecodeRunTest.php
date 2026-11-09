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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Exception\PduElementsException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Exception\FilterTooWideException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecodeRun;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ReceivedAsn1Trait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class FilterDecodeRunTest extends TestCase
{
    use ReceivedAsn1Trait;
    use ServerContainerTrait;

    private FilterDecodeRun $subject;

    protected function setUp(): void
    {
        $this->subject = new FilterDecodeRun(
            new DecodeContext(),
            $this->fromContainer(FilterDecoder::class),
        );
    }

    public function testItStartsOutsideOfAnyEnclosingFilter(): void
    {
        self::assertSame(
            0,
            $this->subject->depth(),
        );
    }

    public function testItDecodesAnEnclosedFilter(): void
    {
        self::assertEquals(
            Filters::present('cn'),
            $this->subject->decodeEnclosed(Filters::present('cn')->toAsn1()),
        );
    }

    public function testItLeavesTheDepthAsItWasOnceAnEnclosedFilterIsDecoded(): void
    {
        $this->subject->decodeEnclosed(Filters::not(Filters::present('cn'))->toAsn1());

        self::assertSame(
            0,
            $this->subject->depth(),
        );
    }

    public function testItRefusesAnEnclosedFilterItDoesNotRecognize(): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->decodeEnclosed(Asn1::context(
            10,
            Asn1::octetString('foo'),
        ));
    }

    public function testItCountsItemsUpToTheMaximum(): void
    {
        $this->countEqualities(FilterDecoder::MAX_ITEMS);

        $this->expectException(FilterTooWideException::class);
        $this->expectExceptionMessage('The filter holds more than 1000 items.');

        $this->subject->countItem(Filters::present('cn'));
    }

    public function testItCountsASubstringOncePerPart(): void
    {
        $this->countEqualities(FilterDecoder::MAX_ITEMS - 3);
        $this->subject->countItem(Filters::substring(
            'cn',
            'a',
            'z',
            'm',
        ));

        $this->expectException(FilterTooWideException::class);

        $this->subject->countItem(Filters::present('cn'));
    }

    public function testItCompletesAFilterWhoseElementsFitTheItemsLeft(): void
    {
        $this->countEqualities(FilterDecoder::MAX_ITEMS - 2);

        self::assertCount(
            2,
            $this->subject->completeWithinItems(
                self::incomplete(Filters::or(
                    Filters::present('cn'),
                    Filters::present('sn'),
                )),
                AbstractType::TAG_TYPE_SET,
            )->getChildren(),
        );
    }

    public function testItRefusesAFilterWhoseElementsOutnumberTheItemsLeftBeforeBuildingThem(): void
    {
        $this->countEqualities(FilterDecoder::MAX_ITEMS - 2);

        try {
            $this->subject->completeWithinItems(
                self::incomplete(Filters::or(
                    Filters::present('cn'),
                    Filters::present('sn'),
                    Filters::present('uid'),
                )),
                AbstractType::TAG_TYPE_SET,
            );
            self::fail('The filter should have been refused.');
        } catch (FilterTooWideException $e) {
            self::assertSame(
                'The filter holds more than 1000 items.',
                $e->getMessage(),
            );
            self::assertInstanceOf(
                PduElementsException::class,
                $e->getPrevious(),
            );
        }
    }

    public function testItLeavesRoomForTheElementsThatAreNotItems(): void
    {
        $this->countEqualities(FilterDecoder::MAX_ITEMS - 3);

        self::assertCount(
            2,
            $this->subject->completeWithinItems(
                self::incomplete(Filters::substring(
                    'cn',
                    'a',
                    'z',
                    'm',
                )),
                AbstractType::TAG_TYPE_SEQUENCE,
                otherElements: 2,
            )->getChildren(),
        );
    }

    private static function incomplete(FilterInterface $filter): IncompleteType
    {
        $type = self::received($filter->toAsn1());
        self::assertInstanceOf(
            IncompleteType::class,
            $type,
        );

        return $type;
    }

    private function countEqualities(int $count): void
    {
        for ($i = 0; $i < $count; $i++) {
            $this->subject->countItem(Filters::equal(
                'cn',
                'foo',
            ));
        }
    }
}
