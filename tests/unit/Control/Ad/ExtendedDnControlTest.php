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
use FreeDSx\Ldap\Control\Ad\ExtendedDnControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class ExtendedDnControlTest extends TestCase
{
    private ExtendedDnControl $subject;

    protected function setUp(): void
    {
        $this->subject = new ExtendedDnControl();
    }

    public function test_it_should_set_whether_or_not_to_use_hex_format(): void
    {
        $this->subject->setUseHexFormat(true);

        self::assertTrue($this->subject->getUseHexFormat());
    }

    public function test_it_should_not_use_hex_format_by_default(): void
    {
        self::assertFalse($this->subject->getUseHexFormat());
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_EXTENDED_DN),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1)
                )))
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            new ExtendedDnControl(),
            ExtendedDnControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_EXTENDED_DN),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1)
                )))
            ))->setValue(null)
        );
    }

    public function test_it_should_be_constructed_from_asn1_when_the_empty_value_form_is_used(): void
    {
        self::assertEquals(
            new ExtendedDnControl(),
            ExtendedDnControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_EXTENDED_DN),
                Asn1::boolean(false)
            ))->setValue(null)
        );
    }
}
