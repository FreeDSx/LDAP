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
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\SyncRequestControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SyncRequestControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private SyncRequestControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SyncRequestControlDecoder::class);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesTheModeCookieAndReloadHint(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_REQUEST,
                Asn1::sequence(
                    Asn1::enumerated(SyncRequestControl::MODE_REFRESH_AND_PERSIST),
                    Asn1::octetString('omnomnom'),
                    Asn1::boolean(true),
                ),
                true,
            ),
            $this->context,
        );

        self::assertSame(
            [SyncRequestControl::MODE_REFRESH_AND_PERSIST, 'omnomnom', true, true],
            [
                $control->getMode(),
                $control->getCookie(),
                $control->getReloadHint(),
                $control->getCriticality(),
            ],
        );
    }

    public function testItKeepsAReceivedCriticalityOfFalse(): void
    {
        self::assertFalse($this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_REQUEST,
                Asn1::sequence(Asn1::enumerated(SyncRequestControl::MODE_REFRESH_ONLY)),
            ),
            $this->context,
        )->getCriticality());
    }

    public function testItRefusesAModeWiderThanAnInteger(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The sync request control mode is not an integer.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_REQUEST,
                Asn1::sequence(new EnumeratedType('18446744073709551616')),
            ),
            $this->context,
        );
    }

    #[DataProvider('malformedValues')]
    public function testItRefusesAMalformedValue(
        SequenceType $value,
        string $message,
    ): void {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage($message);

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_REQUEST,
                $value,
            ),
            $this->context,
        );
    }

    /**
     * @return iterable<string, array{SequenceType, string}>
     */
    public static function malformedValues(): iterable
    {
        yield 'too many values' => [
            Asn1::sequence(
                Asn1::enumerated(1),
                Asn1::octetString('foo'),
                Asn1::boolean(true),
                Asn1::boolean(false),
            ),
            'Expected a sequence type with 2 or less values for a sync request control value.',
        ];
        yield 'no mode' => [
            Asn1::sequence(Asn1::octetString('foo')),
            'Expected an enumerated type for the sync request mode.',
        ];
    }
}
