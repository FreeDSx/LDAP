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

namespace Tests\Unit\FreeDSx\Ldap\Control\Vlv;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Vlv\VlvControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class VlvControlTest extends TestCase
{
    private VlvControl $subject;

    protected function setUp(): void
    {
        $this->subject = new VlvControl(
            before: 10,
            after: 9,
            offset: 8,
            count: 0,
        );
    }

    public function test_it_should_have_a_count_of_zero_by_default(): void
    {
        self::assertSame(
            0,
            $this->subject->getCount(),
        );
    }

    public function test_it_should_get_and_set_the_value_for_after(): void
    {
        $this->subject->setAfter(9);

        self::assertSame(
            9,
            $this->subject->getAfter(),
        );
    }

    public function test_it_should_get_and_set_the_value_for_before(): void
    {
        $this->subject->setBefore(20);

        self::assertSame(
            20,
            $this->subject->getBefore(),
        );
    }

    public function test_it_should_get_and_set_the_value_for_the_offset(): void
    {
        $this->subject->setOffset(16);

        self::assertSame(
            16,
            $this->subject->getOffset(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_VLV),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(10),
                    Asn1::integer(9),
                    Asn1::context(0, Asn1::sequence(
                        Asn1::integer(8),
                        Asn1::integer(0)
                    ))
                )))
            ),
            $this->subject->toAsn1(),
        );
    }
}
