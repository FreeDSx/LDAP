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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Decoder\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Asn1\Type\SequenceType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\SortingResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SortingResponseControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private SortingResponseControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SortingResponseControlDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheResultAndAttribute(): void
    {
        self::assertEquals(
            new SortingResponseControl(
                0,
                'cn',
            ),
            $this->subject->decode(
                self::encodedControl(
                    Control::OID_SORTING_RESPONSE,
                    Asn1::sequence(
                        Asn1::enumerated(0),
                        Asn1::context(
                            0,
                            Asn1::octetString('cn'),
                        ),
                    ),
                ),
                $this->context,
            )->setValue(null),
        );
    }

    public function testItDecodesAResultWithNoAttribute(): void
    {
        self::assertNull($this->subject->decode(
            self::encodedControl(
                Control::OID_SORTING_RESPONSE,
                Asn1::sequence(Asn1::enumerated(0)),
            ),
            $this->context,
        )->getAttribute());
    }

    #[RequiresPhpExtension('gmp')]
    public function testItRefusesAResultWiderThanAnInteger(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The server side sorting response result is not an integer.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SORTING_RESPONSE,
                Asn1::sequence(new EnumeratedType('18446744073709551616')),
            ),
            $this->context,
        );
    }

    #[DataProvider('nonStringAttributes')]
    public function testItRefusesAnAttributeThatIsNotAString(SequenceType $value): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The server side sorting response attribute is not a string.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SORTING_RESPONSE,
                $value,
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{SequenceType}>
     */
    public static function nonStringAttributes(): iterable
    {
        yield 'an integer' => [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::integer(1),
        )];
        yield 'a boolean' => [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::boolean(true),
        )];
        yield 'a sequence' => [Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::sequence(),
        )];
    }

    #[DataProvider('malformedValues')]
    public function testItRefusesAMalformedValue(SequenceType $value): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The server side sorting response is malformed.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SORTING_RESPONSE,
                $value,
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{SequenceType}>
     */
    public static function malformedValues(): iterable
    {
        yield 'no result' => [Asn1::sequence()];
        yield 'a result that is not enumerated' => [Asn1::sequence(Asn1::integer(0))];
    }
}
