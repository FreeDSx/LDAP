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
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\PwdPolicyResponseControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class PwdPolicyResponseControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private PwdPolicyResponseControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(PwdPolicyResponseControlDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheTimeBeforeExpirationAndError(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_PWD_POLICY,
                Asn1::sequence(
                    Asn1::context(
                        0,
                        Asn1::sequence(Asn1::context(
                            0,
                            Asn1::integer(100),
                        )),
                    ),
                    Asn1::context(
                        1,
                        Asn1::enumerated(2),
                    ),
                ),
            ),
            $this->context,
        );

        self::assertSame(
            [100, null, 2, Control::OID_PWD_POLICY, false],
            [
                $control->getTimeBeforeExpiration(),
                $control->getGraceAttemptsRemaining(),
                $control->getError(),
                $control->getTypeOid(),
                $control->getCriticality(),
            ],
        );
    }

    public function testItDecodesTheGraceAuthenticationsRemaining(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_PWD_POLICY,
                Asn1::sequence(Asn1::context(
                    0,
                    Asn1::sequence(Asn1::context(
                        1,
                        Asn1::integer(3),
                    )),
                )),
            ),
            $this->context,
        );

        self::assertSame(
            [null, 3, null],
            [
                $control->getTimeBeforeExpiration(),
                $control->getGraceAttemptsRemaining(),
                $control->getError(),
            ],
        );
    }

    public function testItKeepsAnEarlierWarningWhenALaterOneHasNoneItRecognizes(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_PWD_POLICY,
                Asn1::sequence(
                    Asn1::context(
                        0,
                        Asn1::sequence(Asn1::context(
                            1,
                            Asn1::integer(3),
                        )),
                    ),
                    Asn1::context(
                        0,
                        Asn1::sequence(Asn1::context(
                            2,
                            Asn1::integer(5),
                        )),
                    ),
                ),
            ),
            $this->context,
        );

        self::assertSame(
            3,
            $control->getGraceAttemptsRemaining(),
        );
    }

    public function testItRefusesAComponentThatIsNotContextTagged(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The ASN1 structure for the pwdPolicy control is malformed.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_PWD_POLICY,
                Asn1::sequence(Asn1::integer(1)),
            ),
            $this->context,
        );
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
                Control::OID_PWD_POLICY,
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
        yield 'time before expiration' => [
            Asn1::sequence(Asn1::context(
                0,
                Asn1::sequence(Asn1::context(
                    0,
                    Asn1::integer('18446744073709551616'),
                )),
            )),
            'The pwdPolicy control time before expiration is not an integer.',
        ];
        yield 'grace authentications remaining' => [
            Asn1::sequence(Asn1::context(
                0,
                Asn1::sequence(Asn1::context(
                    1,
                    Asn1::integer('18446744073709551616'),
                )),
            )),
            'The pwdPolicy control grace authentications remaining is not an integer.',
        ];
        yield 'error' => [
            Asn1::sequence(Asn1::context(
                1,
                new EnumeratedType('18446744073709551616'),
            )),
            'The pwdPolicy control error is not an integer.',
        ];
    }
}
