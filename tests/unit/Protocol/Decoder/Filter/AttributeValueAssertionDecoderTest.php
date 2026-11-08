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
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use FreeDSx\Ldap\Protocol\Decoder\Filter\AttributeValueAssertionDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecodeRun;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Search\Filter\ApproximateFilter;
use FreeDSx\Ldap\Search\Filter\AttributeValueAssertionInterface;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;
use FreeDSx\Ldap\Search\Filter\LessThanOrEqualFilter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ReceivedAsn1Trait;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class AttributeValueAssertionDecoderTest extends TestCase
{
    use ReceivedAsn1Trait;
    use ServerContainerTrait;
    use TrailingComponentTrait;

    /**
     * @var AttributeValueAssertionDecoder<EqualityFilter>
     */
    private AttributeValueAssertionDecoder $subject;

    private DecodeContext $context;

    private FilterDecodeRun $run;

    protected function setUp(): void
    {
        $this->subject = new AttributeValueAssertionDecoder(EqualityFilter::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
        $this->run = new FilterDecodeRun(
            $this->context,
            $this->fromContainer(FilterDecoder::class),
        );
    }

    public function testItDecodesTheAttributeAndTheValue(): void
    {
        self::assertEquals(
            new EqualityFilter(
                'cn',
                'foo',
            ),
            $this->subject->decode(
                self::received((new EqualityFilter(
                    'cn',
                    'foo',
                ))->toAsn1()),
                $this->run,
            ),
        );
    }

    public function testItDecodesAnAssertionThatIsAlreadyDecoded(): void
    {
        self::assertEquals(
            new EqualityFilter(
                'cn',
                'foo',
            ),
            $this->subject->decode(
                (new EqualityFilter(
                    'cn',
                    'foo',
                ))->toAsn1(),
                $this->run,
            ),
        );
    }

    public function testItIgnoresATrailingComponentItDoesNotRecognize(): void
    {
        self::assertEquals(
            new EqualityFilter(
                'cn',
                'foo',
            ),
            $this->subject->decode(
                self::received(self::withTrailingComponent((new EqualityFilter(
                    'cn',
                    'foo',
                ))->toAsn1())),
                $this->run,
            ),
        );
    }

    public function testItDecodesTheAssertionACompareCarriesOutsideOfAnyFilter(): void
    {
        self::assertEquals(
            new EqualityFilter(
                'cn',
                'foo',
            ),
            $this->subject->decodeAssertion(
                Asn1::sequence(
                    Asn1::octetString('cn'),
                    Asn1::octetString('foo'),
                ),
                $this->context,
            ),
        );
    }

    /**
     * @param class-string<AttributeValueAssertionInterface&FilterInterface> $filterClass
     */
    #[DataProvider('assertionFilters')]
    public function testItBuildsTheKindOfFilterItIsGiven(
        string $filterClass,
        AttributeValueAssertionInterface&FilterInterface $filter,
    ): void {
        self::assertEquals(
            $filter,
            (new AttributeValueAssertionDecoder($filterClass))->decode(
                self::received($filter->toAsn1()),
                $this->run,
            ),
        );
    }

    /**
     * @return iterable<string, array{
     *     class-string<AttributeValueAssertionInterface&FilterInterface>,
     *     AttributeValueAssertionInterface&FilterInterface,
     * }>
     */
    public static function assertionFilters(): iterable
    {
        yield 'approximate' => [
            ApproximateFilter::class,
            new ApproximateFilter(
                'cn',
                'foo',
            ),
        ];
        yield 'greater or equal' => [
            GreaterThanOrEqualFilter::class,
            new GreaterThanOrEqualFilter(
                'uidNumber',
                '10',
            ),
        ];
        yield 'less or equal' => [
            LessThanOrEqualFilter::class,
            new LessThanOrEqualFilter(
                'uidNumber',
                '10',
            ),
        ];
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedAssertions')]
    public function testItRefusesAnAssertionThatIsMalformed(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The attribute value assertion is malformed.');

        $this->subject->decode(
            $type,
            $this->run,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>}>
     */
    public static function malformedAssertions(): iterable
    {
        yield 'an octet string' => [Asn1::octetString('foo')];
        yield 'no value' => [Asn1::sequence(Asn1::octetString('cn'))];
        yield 'an attribute that is not an octet string' => [Asn1::sequence(
            Asn1::integer(1),
            Asn1::octetString('foo'),
        )];
        yield 'a value that is not an octet string' => [Asn1::sequence(
            Asn1::octetString('cn'),
            Asn1::integer(1),
        )];
    }
}
