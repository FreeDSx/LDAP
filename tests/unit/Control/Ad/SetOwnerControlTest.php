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

namespace Tests\Unit\FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Ad\SetOwnerControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class SetOwnerControlTest extends TestCase
{
    private SetOwnerControl $subject;

    protected function setUp(): void
    {
        $this->subject = new SetOwnerControl('foo');
    }

    public function test_it_should_get_the_sid(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getSid(),
        );
    }

    public function test_it_should_set_the_sid(): void
    {
        $this->subject->setSid('bar');

        self::assertSame(
            'bar',
            $this->subject->getSid(),
        );
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            $this->subject->toAsn1(),
            Asn1::sequence(
                Asn1::octetString(Control::OID_SET_OWNER),
                Asn1::boolean(true),
                Asn1::octetString($encoder->encode(Asn1::octetString('foo')))
            )
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            new SetOwnerControl('foo'),
            SetOwnerControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_SET_OWNER),
                Asn1::boolean(true),
                Asn1::octetString($encoder->encode(Asn1::octetString('foo')))
            ))->setValue(null)
        );
    }
}
