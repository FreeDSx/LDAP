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
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecodeRun;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Filter\SubstringFilterDecoder;
use FreeDSx\Ldap\Search\Filter\SubstringFilter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ReceivedAsn1Trait;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SubstringFilterDecoderTest extends TestCase
{
    use ReceivedAsn1Trait;
    use ServerContainerTrait;
    use TrailingComponentTrait;

    private SubstringFilterDecoder $subject;

    private FilterDecodeRun $run;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SubstringFilterDecoder::class);
        $this->run = new FilterDecodeRun(
            $this->fromContainer(DecodeContextFactory::class)->create(),
            $this->fromContainer(FilterDecoder::class),
        );
    }

    #[DataProvider('substrings')]
    public function testItDecodesEachPartItMatches(SubstringFilter $filter): void
    {
        self::assertEquals(
            $filter,
            $this->subject->decode(
                self::received($filter->toAsn1()),
                $this->run,
            ),
        );
    }

    /**
     * @return iterable<string, array{SubstringFilter}>
     */
    public static function substrings(): iterable
    {
        yield 'every part' => [new SubstringFilter(
            'cn',
            'foo',
            'bar',
            'foobar',
            'wee',
        )];
        yield 'an initial and a final part' => [new SubstringFilter(
            'cn',
            'foo',
            'bar',
        )];
        yield 'an initial part' => [new SubstringFilter(
            'cn',
            'foo',
        )];
        yield 'a final part' => [new SubstringFilter(
            'cn',
            null,
            'foo',
        )];
        yield 'any parts' => [new SubstringFilter(
            'cn',
            null,
            null,
            'foo',
            'bar',
        )];
    }

    public function testItDecodesASubstringFilterThatIsAlreadyDecoded(): void
    {
        $filter = new SubstringFilter(
            'cn',
            'foo',
            'bar',
            'wee',
        );

        self::assertEquals(
            $filter,
            $this->subject->decode(
                $filter->toAsn1(),
                $this->run,
            ),
        );
    }

    public function testItIgnoresATrailingComponentItDoesNotRecognize(): void
    {
        $filter = new SubstringFilter(
            'cn',
            'foo',
            'bar',
        );

        self::assertEquals(
            $filter,
            $this->subject->decode(
                self::received(self::withTrailingComponent($filter->toAsn1())),
                $this->run,
            ),
        );
    }

    public function testItRefusesASubstringFilterWithoutAnyParts(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The substring type is malformed');

        $this->subject->decode(
            Asn1::sequence(Asn1::octetString('cn')),
            $this->run,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedSubstrings')]
    public function testItRefusesASubstringFilterThatIsMalformed(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The substring filter is malformed.');

        $this->subject->decode(
            $type,
            $this->run,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>}>
     */
    public static function malformedSubstrings(): iterable
    {
        yield 'an attribute that is not an octet string' => [Asn1::sequence(
            Asn1::integer(1),
            Asn1::sequence(self::part(0)),
        )];
        yield 'parts that are not a sequence' => [Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::octetString('foo'),
        )];
        yield 'an empty sequence of parts' => [Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::sequence(),
        )];
        yield 'a part that is not context tagged' => [Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::sequence(Asn1::octetString('foo')),
        )];
        yield 'a part it does not recognize' => [Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::sequence(self::part(3)),
        )];
        yield 'two initial parts' => [Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::sequence(
                self::part(0),
                self::part(0),
            ),
        )];
        yield 'two final parts' => [Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::sequence(
                self::part(2),
                self::part(2),
            ),
        )];
    }

    /**
     * @return AbstractType<mixed>
     */
    private static function part(int $tagNumber): AbstractType
    {
        return Asn1::context(
            $tagNumber,
            Asn1::octetString('foo'),
        );
    }
}
