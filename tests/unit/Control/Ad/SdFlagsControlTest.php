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
use FreeDSx\Ldap\Control\Ad\SdFlagsControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;

class SdFlagsControlTest extends \PHPUnit\Framework\TestCase
{
    protected SdFlagsControl $subject;
    protected function setUp(): void
    {
        $this->subject = new SdFlagsControl(SdFlagsControl::DACL_SECURITY_INFORMATION);
    }

    public function test_it_should_get_the_flags(): void
    {
        self::assertSame(
            SdFlagsControl::DACL_SECURITY_INFORMATION,
            $this->subject->getFlags(),
        );
    }

    public function test_it_should_set_the_flags(): void
    {
        $this->subject->setFlags(SdFlagsControl::SACL_SECURITY_INFORMATION);

        self::assertSame(
            SdFlagsControl::SACL_SECURITY_INFORMATION,
            $this->subject->getFlags(),
        );
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            $this->subject->toAsn1(),
            Asn1::sequence(
                Asn1::octetString(Control::OID_SD_FLAGS),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(4)
                )))
            )
        );
    }
}
