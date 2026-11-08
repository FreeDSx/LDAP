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
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Decoder\Control\ControlFields;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\TrailingComponentTrait;

final class ControlFieldsTest extends TestCase
{
    use TrailingComponentTrait;

    public function testItReadsTheTypeCriticalityAndValue(): void
    {
        self::assertEquals(
            new ControlFields(
                '1.2.3',
                true,
                'foo',
            ),
            ControlFields::of(Asn1::sequence(
                Asn1::octetString('1.2.3'),
                Asn1::boolean(true),
                Asn1::octetString('foo'),
            )),
        );
    }

    public function testItReadsTheValueWhenTheCriticalityIsAbsent(): void
    {
        self::assertEquals(
            new ControlFields(
                '1.2.3',
                false,
                'foo',
            ),
            ControlFields::of(Asn1::sequence(
                Asn1::octetString('1.2.3'),
                Asn1::octetString('foo'),
            )),
        );
    }

    public function testItReadsAControlWithNoValue(): void
    {
        self::assertEquals(
            new ControlFields(
                '1.2.3',
                false,
                null,
            ),
            ControlFields::of(Asn1::sequence(Asn1::octetString('1.2.3'))),
        );
    }

    public function testItIgnoresATrailingComponentItDoesNotRecognize(): void
    {
        self::assertEquals(
            new ControlFields(
                '1.2.3',
                true,
                'foo',
            ),
            ControlFields::of(self::withTrailingComponent(Asn1::sequence(
                Asn1::octetString('1.2.3'),
                Asn1::boolean(true),
                Asn1::octetString('foo'),
            ))),
        );
    }

    public function testItRefusesAControlWithoutATypeOid(): void
    {
        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The received control is malformed. The control type OID is missing.');

        ControlFields::of(Asn1::sequence(Asn1::boolean(true)));
    }

    public function testItSetsTheReceivedFieldsOnADecodedControl(): void
    {
        $control = (new ControlFields(
            '1.2.3',
            true,
            'foo',
        ))->applyTo(new PagingControl(10));

        self::assertSame(
            ['1.2.3', true, 'foo', 10],
            [
                $control->getTypeOid(),
                $control->getCriticality(),
                $control->getValue(),
                $control->getSize(),
            ],
        );
    }
}
