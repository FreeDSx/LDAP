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
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\SyncStateControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SyncStateControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private SyncStateControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SyncStateControlDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheStateEntryUuidAndCookie(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_STATE,
                Asn1::sequence(
                    Asn1::enumerated(SyncStateControl::STATE_ADD),
                    Asn1::octetString('foo'),
                    Asn1::octetString('omnomnom'),
                ),
            ),
            $this->context,
        );

        self::assertSame(
            [SyncStateControl::STATE_ADD, 'foo', 'omnomnom', Control::OID_SYNC_STATE],
            [
                $control->getState(),
                $control->getEntryUuid(),
                $control->getCookie(),
                $control->getTypeOid(),
            ],
        );
    }

    public function testItDecodesAStateWithNoCookie(): void
    {
        self::assertNull($this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_STATE,
                Asn1::sequence(
                    Asn1::enumerated(SyncStateControl::STATE_PRESENT),
                    Asn1::octetString('foo'),
                ),
            ),
            $this->context,
        )->getCookie());
    }

    #[RequiresPhpExtension('gmp')]
    public function testItRefusesAStateWiderThanAnInteger(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The sync state control state is not an integer.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_STATE,
                Asn1::sequence(
                    new EnumeratedType('18446744073709551616'),
                    Asn1::octetString('foo'),
                ),
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
                Control::OID_SYNC_STATE,
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
        yield 'too few values' => [
            Asn1::sequence(Asn1::enumerated(0)),
            'Expected a sequence type with 2 or 3 values for a sync state control value.',
        ];
        yield 'a state that is not enumerated' => [
            Asn1::sequence(
                Asn1::integer(0),
                Asn1::octetString('foo'),
            ),
            'Expected an enumerated type for the state control value.',
        ];
        yield 'an entry UUID that is not an octet string' => [
            Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::integer(1),
            ),
            'Expected an octet string type for the state control value.',
        ];
        yield 'a cookie that is not an octet string' => [
            Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('foo'),
                Asn1::integer(1),
            ),
            'Expected an octet string type for the sync state cookie value.',
        ];
    }
}
