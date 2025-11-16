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
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class VlvResponseControlTest extends TestCase
{
    private VlvResponseControl $subject;

    protected function setUp(): void
    {
        $this->subject = new VlvResponseControl(
            offset: 10,
            count: 9,
            result: 0,
        );
    }

    public function test_it_should_get_the_offset(): void
    {
        self::assertSame(
            10,
            $this->subject->getOffset(),
        );
    }

    public function test_it_should_get_the_count(): void
    {
        self::assertSame(
            9,
            $this->subject->getCount(),
        );
    }

    public function test_it_should_get_the_context_id(): void
    {
        self::assertNull($this->subject->getContextId());
    }

    public function test_it_should_get_the_result(): void
    {
        self::assertSame(
            0,
            $this->subject->getResult(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            new VlvResponseControl(1, 300, 0, 'foo'),
            VlvResponseControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_VLV_RESPONSE),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(1),
                    Asn1::integer(300),
                    Asn1::enumerated(0),
                    Asn1::octetString('foo')
                )))
            ))->setValue(null)
        );
    }
}
