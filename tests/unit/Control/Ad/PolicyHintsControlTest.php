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
use FreeDSx\Ldap\Control\Ad\PolicyHintsControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class PolicyHintsControlTest extends TestCase
{
    private PolicyHintsControl $subject;

    protected function setUp(): void
    {
        $this->subject = new PolicyHintsControl();
    }

    public function test_it_should_be_enabled_by_default(): void
    {
        self::assertTrue($this->subject->getIsEnabled());
    }

    public function test_it_should_set_whether_or_not_it_is_enabled(): void
    {
        $this->subject->setIsEnabled(false);

        self::assertFalse($this->subject->getIsEnabled());
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            $this->subject->toAsn1(),
            Asn1::sequence(
                Asn1::octetString(Control::OID_POLICY_HINTS),
                Asn1::boolean(true),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1)
                )))
            )
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            new PolicyHintsControl(),
            PolicyHintsControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_POLICY_HINTS),
                Asn1::boolean(true),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1)
                )))
            ))->setValue(null)
        );
    }
}
