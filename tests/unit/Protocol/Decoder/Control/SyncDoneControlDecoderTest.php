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
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\SyncDoneControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\EncodedControlTrait;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class SyncDoneControlDecoderTest extends TestCase
{
    use EncodedControlTrait;
    use ServerContainerTrait;

    private SyncDoneControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = $this->fromContainer(SyncDoneControlDecoder::class);
        $this->context = new DecodeContext();
    }

    public function testItDecodesTheCookieAndRefreshDeletes(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_DONE,
                Asn1::sequence(
                    Asn1::octetString('omnomnom'),
                    Asn1::boolean(true),
                ),
            ),
            $this->context,
        );

        self::assertSame(
            ['omnomnom', true, Control::OID_SYNC_DONE],
            [
                $control->getCookie(),
                $control->getRefreshDeletes(),
                $control->getTypeOid(),
            ],
        );
    }

    public function testItDecodesAnEmptyValue(): void
    {
        $control = $this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_DONE,
                Asn1::sequence(),
            ),
            $this->context,
        );

        self::assertSame(
            [null, false],
            [
                $control->getCookie(),
                $control->getRefreshDeletes(),
            ],
        );
    }

    public function testItRefusesTooManyValues(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('Expected a sequence type with 2 or less values for a sync done control value.');

        $this->subject->decode(
            self::encodedControl(
                Control::OID_SYNC_DONE,
                Asn1::sequence(
                    Asn1::octetString('foo'),
                    Asn1::boolean(true),
                    Asn1::boolean(false),
                ),
            ),
            $this->context,
        );
    }
}
