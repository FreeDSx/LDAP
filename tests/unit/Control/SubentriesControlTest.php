<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\SubentriesControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class SubentriesControlTest extends TestCase
{
    private SubentriesControl $subject;

    protected function setUp(): void
    {
        $this->subject = new SubentriesControl();
    }

    public function test_it_should_have_a_default_visibility_of_true(): void
    {
        self::assertTrue($this->subject->getIsVisible());
    }

    public function test_it_should_set_the_visibility(): void
    {
        $this->subject->setIsVisible(false);

        self::assertFalse($this->subject->getIsVisible());
    }

    public function test_it_should_have_the_subentries_oid(): void
    {
        self::assertSame(
            Control::OID_SUBENTRIES,
            $this->subject->getTypeOid(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_SUBENTRIES),
                Asn1::boolean(true),
                Asn1::octetString($encoder->encode(Asn1::boolean(true)))
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $result = SubentriesControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SUBENTRIES),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::boolean(true)))
        ));

        self::assertTrue($result->getIsVisible());
        self::assertSame(
            Control::OID_SUBENTRIES,
            $result->getTypeOid()
        );
    }
}
