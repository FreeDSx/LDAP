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
use FreeDSx\Ldap\Protocol\Decoder\Filter\MatchingRuleFilterDecoder;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\ReceivedAsn1Trait;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class MatchingRuleFilterDecoderTest extends TestCase
{
    use ReceivedAsn1Trait;
    use ServerContainerTrait;
    use TrailingComponentTrait;

    private MatchingRuleFilterDecoder $subject;

    private FilterDecodeRun $run;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(MatchingRuleFilterDecoder::class);
        $this->run = new FilterDecodeRun(
            new DecodeContext(),
            $this->fromContainer(FilterDecoder::class),
        );
    }

    #[DataProvider('matchingRuleFilters')]
    public function testItDecodesEachFieldItCarries(MatchingRuleFilter $filter): void
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
     * @return iterable<string, array{MatchingRuleFilter}>
     */
    public static function matchingRuleFilters(): iterable
    {
        yield 'every field' => [new MatchingRuleFilter(
            '2.5.13.2',
            'cn',
            'foo',
            true,
        )];
        yield 'a matching rule alone' => [new MatchingRuleFilter(
            '2.5.13.2',
            null,
            'foo',
        )];
        yield 'an attribute alone' => [new MatchingRuleFilter(
            null,
            'cn',
            'foo',
        )];
    }

    public function testItDecodesAMatchingRuleFilterThatIsAlreadyDecoded(): void
    {
        $filter = new MatchingRuleFilter(
            '2.5.13.2',
            'cn',
            'foo',
            true,
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
        $filter = new MatchingRuleFilter(
            '2.5.13.2',
            'cn',
            'foo',
            true,
        );

        self::assertEquals(
            $filter,
            $this->subject->decode(
                self::received(self::withTrailingComponent($filter->toAsn1())),
                $this->run,
            ),
        );
    }

    public function testItRefusesAMatchingRuleFilterWithoutAnyFields(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The matching rule filter is malformed');

        $this->subject->decode(
            Asn1::sequence(),
            $this->run,
        );
    }

    /**
     * @param AbstractType<mixed> $type
     */
    #[DataProvider('malformedMatchingRuleFilters')]
    public function testItRefusesAMatchingRuleFilterThatIsMalformed(AbstractType $type): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The matching rule filter is malformed.');

        $this->subject->decode(
            $type,
            $this->run,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>}>
     */
    public static function malformedMatchingRuleFilters(): iterable
    {
        yield 'no match value' => [Asn1::sequence(Asn1::context(
            1,
            Asn1::octetString('2.5.13.2'),
        ))];
        yield 'a matching rule that is not an octet string' => [Asn1::sequence(
            Asn1::context(
                1,
                Asn1::integer(1),
            ),
            Asn1::context(
                3,
                Asn1::octetString('foo'),
            ),
        )];
        yield 'an attribute that is not an octet string' => [Asn1::sequence(
            Asn1::context(
                2,
                Asn1::integer(1),
            ),
            Asn1::context(
                3,
                Asn1::octetString('foo'),
            ),
        )];
        yield 'dn attributes that are not a boolean' => [Asn1::sequence(
            Asn1::context(
                3,
                Asn1::octetString('foo'),
            ),
            Asn1::context(
                4,
                Asn1::octetString('TRUE'),
            ),
        )];
    }
}
