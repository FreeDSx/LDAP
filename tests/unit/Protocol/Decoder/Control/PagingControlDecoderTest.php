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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\PagingControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class PagingControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private PagingControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(PagingControlDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheSizeAndCookie(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_PAGING,
                Asn1::sequence(
                    Asn1::integer(1),
                    Asn1::octetString('foobar'),
                ),
            ),
            $this->context,
        );

        self::assertSame(
            [1, 'foobar'],
            [
                $control->getSize(),
                $control->getCookie(),
            ],
        );
    }

    public function testItKeepsTheReceivedTypeAndCriticality(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_PAGING,
                Asn1::sequence(
                    Asn1::integer(1),
                    Asn1::octetString(''),
                ),
                true,
            ),
            $this->context,
        );

        self::assertSame(
            [Control::OID_PAGING, true],
            [
                $control->getTypeOid(),
                $control->getCriticality(),
            ],
        );
    }

    public function testItRefusesAControlWithoutAValue(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The received control is malformed. Unable to get the encoded value.');

        $this->subject->decode(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PAGING),
                Asn1::boolean(false),
            ),
            $this->context,
        );
    }

    #[RequiresPhpExtension('gmp')]
    public function testItRefusesASizeWiderThanAnInteger(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The paged control size is not an integer.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_PAGING,
                Asn1::sequence(
                    Asn1::integer('18446744073709551616'),
                    Asn1::octetString(''),
                ),
            ),
            $this->context,
        );
    }

    /**
     * @param AbstractType<mixed> $value
     */
    #[DataProvider('malformedValues')]
    public function testItRefusesAMalformedValue(
        AbstractType $value,
        string $message,
    ): void {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage($message);

        $this->subject->decode(
            self::encodedControl(
                Control::OID_PAGING,
                $value,
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{AbstractType<mixed>, string}>
     */
    public static function malformedValues(): iterable
    {
        yield 'not a sequence' => [
            Asn1::octetString('foo'),
            'A paged control value must be a sequence type with 2 children.',
        ];
        yield 'a size that is not an integer' => [
            Asn1::sequence(
                Asn1::octetString('1'),
                Asn1::octetString(''),
            ),
            'A paged control value sequence 0 must be an integer type.',
        ];
        yield 'a cookie that is not an octet string' => [
            Asn1::sequence(
                Asn1::integer(1),
                Asn1::integer(1),
            ),
            'A paged control value sequence 1 must be an octet string type.',
        ];
    }
}
