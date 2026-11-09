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
use FreeDSx\Ldap\Protocol\Decoder\Filter\NotFilterDecoder;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ReceivedAsn1Trait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class NotFilterDecoderTest extends TestCase
{
    use ReceivedAsn1Trait;
    use ServerContainerTrait;

    private NotFilterDecoder $subject;

    private FilterDecodeRun $run;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(NotFilterDecoder::class);
        $this->run = new FilterDecodeRun(
            new DecodeContext(),
            $this->fromContainer(FilterDecoder::class),
        );
    }

    public function testItDecodesTheFilterItNegates(): void
    {
        $filter = Filters::not(Filters::equal(
            'cn',
            'foo',
        ));

        self::assertEquals(
            $filter,
            $this->subject->decode(
                self::received($filter->toAsn1()),
                $this->run,
            ),
        );
    }

    public function testItDecodesANotThatIsAlreadyDecoded(): void
    {
        $filter = Filters::not(Filters::present('cn'));

        self::assertEquals(
            $filter,
            $this->subject->decode(
                $filter->toAsn1(),
                $this->run,
            ),
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedNots')]
    public function testItRefusesANotThatIsMalformed(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The not filter is malformed');

        $this->subject->decode(
            $type,
            $this->run,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>}>
     */
    public static function malformedNots(): iterable
    {
        yield 'an octet string' => [Asn1::octetString('foo')];
        yield 'no filter' => [Asn1::sequence()];
        yield 'two filters' => [Asn1::sequence(
            Filters::present('cn')->toAsn1(),
            Filters::present('sn')->toAsn1(),
        )];
    }
}
