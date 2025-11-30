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
use FreeDSx\Ldap\Control\Ad\ExpectedEntryCountControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class ExpectedEntryCountControlTest extends TestCase
{
    private ExpectedEntryCountControl $subject;

    protected function setUp(): void
    {
        $this->subject = new ExpectedEntryCountControl(
            min: 1,
            max: 50,
        );
    }

    public function test_it_should_set_the_maximum(): void
    {
        $this->subject->setMaximum(100);

        self::assertSame(
            100,
            $this->subject->getMaximum(),
        );
    }

    public function test_it_should_get_the_maximum(): void
    {
        self::assertSame(
            50,
            $this->subject->getMaximum(),
        );
    }

    public function test_it_should_set_the_minimum(): void
    {
        $this->subject->setMinimum(100);

        self::assertSame(
            100,
            $this->subject->getMinimum(),
        );
    }

    public function test_it_should_get_the_minimum(): void
    {
        self::assertSame(
            1,
            $this->subject->getMinimum(),
        );
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            $this->subject->toAsn1(),
            Asn1::sequence(
                Asn1::octetString(Control::OID_EXPECTED_ENTRY_COUNT),
                Asn1::boolean(true),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1),
                    Asn1::integer(50)
                )))
            )
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            new ExpectedEntryCountControl(min: 1, max: 50),
            ExpectedEntryCountControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_EXPECTED_ENTRY_COUNT),
                Asn1::boolean(true),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1),
                    Asn1::integer(50)
                )))
            ))->setValue(null)
        );
    }
}
