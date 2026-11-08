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
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Protocol\Decoder\Control\ControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\PagingControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContextFactory;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class ControlDecoderTest extends TestCase
{
    use ServerContainerTrait;

    private ControlDecoder $subject;

    private DecodeContext $context;

    protected function setUp(): void
    {
        $this->subject = new ControlDecoder([
            Control::OID_PAGING => $this->fromContainer(PagingControlDecoder::class),
        ]);
        $this->context = $this->fromContainer(DecodeContextFactory::class)->create();
    }

    public function testItDecodesAControlThroughTheDecoderForItsOid(): void
    {
        self::assertInstanceOf(
            PagingControl::class,
            $this->subject->decode(
                (new PagingControl(
                    10,
                    'cookie',
                ))->toAsn1(),
                $this->context,
            ),
        );
    }

    public function testItDecodesAnyOtherControlAsAGenericControl(): void
    {
        self::assertEquals(
            new Control(
                '1.2.3',
                true,
                'foo',
            ),
            $this->subject->decode(
                Asn1::sequence(
                    Asn1::octetString('1.2.3'),
                    Asn1::boolean(true),
                    Asn1::octetString('foo'),
                ),
                $this->context,
            ),
        );
    }

    public function testItDecodesAGenericControlWithNoValue(): void
    {
        self::assertEquals(
            new Control('1.2.3'),
            $this->subject->decode(
                Asn1::sequence(Asn1::octetString('1.2.3')),
                $this->context,
            ),
        );
    }
}
