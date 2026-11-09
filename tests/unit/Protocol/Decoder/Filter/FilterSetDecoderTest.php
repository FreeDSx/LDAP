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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecodeRun;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterSetDecoder;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ReceivedAsn1Trait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class FilterSetDecoderTest extends TestCase
{
    use ReceivedAsn1Trait;
    use ServerContainerTrait;

    /**
     * @var FilterSetDecoder<AndFilter>
     */
    private FilterSetDecoder $subject;

    private FilterDecodeRun $run;

    protected function setUp(): void
    {
        $this->subject = new FilterSetDecoder(AndFilter::class);
        $this->run = new FilterDecodeRun(
            new DecodeContext(),
            $this->fromContainer(FilterDecoder::class),
        );
    }

    public function testItDecodesEachFilterItEncloses(): void
    {
        $filter = Filters::and(
            Filters::equal(
                'cn',
                'foo',
            ),
            Filters::substring(
                'sn',
                'bar',
                null,
            ),
        );

        self::assertEquals(
            $filter,
            $this->subject->decode(
                self::received($filter->toAsn1()),
                $this->run,
            ),
        );
    }

    public function testItDecodesASetThatIsAlreadyDecoded(): void
    {
        $filter = Filters::and(
            Filters::present('cn'),
            Filters::present('sn'),
        );

        self::assertEquals(
            $filter,
            $this->subject->decode(
                $filter->toAsn1(),
                $this->run,
            ),
        );
    }

    public function testItDecodesASetEnclosingNothing(): void
    {
        self::assertEquals(
            Filters::and(),
            $this->subject->decode(
                self::received(Filters::and()->toAsn1()),
                $this->run,
            ),
        );
    }

    public function testItBuildsTheKindOfSetItIsGiven(): void
    {
        $filter = Filters::or(
            Filters::present('cn'),
            Filters::present('sn'),
        );

        self::assertEquals(
            $filter,
            (new FilterSetDecoder(OrFilter::class))->decode(
                self::received($filter->toAsn1()),
                $this->run,
            ),
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedSets')]
    public function testItRefusesASetThatIsMalformed(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The filter is malformed');

        $this->subject->decode(
            $type,
            $this->run,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>}>
     */
    public static function malformedSets(): iterable
    {
        yield 'an octet string' => [Asn1::octetString('foo')];
        yield 'a sequence' => [Asn1::sequence()];
    }
}
