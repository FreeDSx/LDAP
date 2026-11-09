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
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\VlvResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class VlvResponseControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private VlvResponseControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(VlvResponseControlDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesThePositionCountResultAndContextId(): void
    {
        self::assertEquals(
            new VlvResponseControl(
                1,
                300,
                0,
                'foo',
            ),
            $this->subject->decode(
                self::encodedControl(
                    Control::OID_VLV_RESPONSE,
                    Asn1::sequence(
                        Asn1::integer(1),
                        Asn1::integer(300),
                        Asn1::enumerated(0),
                        Asn1::octetString('foo'),
                    ),
                ),
                $this->context,
            )->setValue(null),
        );
    }

    public function testItDecodesAResponseWithNoContextId(): void
    {
        self::assertNull($this->subject->decode(
            self::encodedControl(
                Control::OID_VLV_RESPONSE,
                Asn1::sequence(
                    Asn1::integer(1),
                    Asn1::integer(300),
                    Asn1::enumerated(0),
                ),
            ),
            $this->context,
        )->getContextId());
    }

    #[DataProvider('wideFields')]
    #[RequiresPhpExtension('gmp')]
    public function testItRefusesAFieldWiderThanAnInteger(
        SequenceType $value,
        string $message,
    ): void {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage($message);

        $this->subject->decode(
            self::encodedControl(
                Control::OID_VLV_RESPONSE,
                $value,
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{SequenceType, string}>
     */
    public static function wideFields(): iterable
    {
        yield 'target position' => [
            Asn1::sequence(
                Asn1::integer('18446744073709551616'),
                Asn1::integer(300),
                Asn1::enumerated(0),
            ),
            'The VLV response target position is not an integer.',
        ];
        yield 'content count' => [
            Asn1::sequence(
                Asn1::integer(1),
                Asn1::integer('18446744073709551616'),
                Asn1::enumerated(0),
            ),
            'The VLV response content count is not an integer.',
        ];
        yield 'result' => [
            Asn1::sequence(
                Asn1::integer(1),
                Asn1::integer(300),
                new EnumeratedType('18446744073709551616'),
            ),
            'The VLV response result is not an integer.',
        ];
    }

    #[DataProvider('malformedValues')]
    public function testItRefusesAMalformedValue(SequenceType $value): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The VLV response value contains an unexpected ASN1 type.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_VLV_RESPONSE,
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
        yield 'a target position that is not an integer' => [Asn1::sequence(
            Asn1::octetString('1'),
            Asn1::integer(300),
            Asn1::enumerated(0),
        )];
        yield 'a content count that is not an integer' => [Asn1::sequence(
            Asn1::integer(1),
            Asn1::octetString('300'),
            Asn1::enumerated(0),
        )];
        yield 'a result that is not enumerated' => [Asn1::sequence(
            Asn1::integer(1),
            Asn1::integer(300),
            Asn1::integer(0),
        )];
        yield 'a context ID that is not an octet string' => [Asn1::sequence(
            Asn1::integer(1),
            Asn1::integer(300),
            Asn1::enumerated(0),
            Asn1::integer(1),
        )];
    }
}
