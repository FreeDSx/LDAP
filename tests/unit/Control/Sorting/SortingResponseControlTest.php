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

namespace Tests\Unit\FreeDSx\Ldap\Control\Sorting;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class SortingResponseControlTest extends TestCase
{
    protected SortingResponseControl $subject;

    protected function setUp(): void
    {
        $this->subject = new SortingResponseControl(
            result: 0,
            attribute: 'cn'
        );
    }

    public function test_it_should_get_the_result(): void
    {
        self::assertSame(
            0,
            $this->subject->getResult(),
        );
    }

    public function test_it_should_get_the_attribute(): void
    {
        self::assertSame(
            'cn',
            $this->subject->getAttribute(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            new SortingResponseControl(0, 'cn'),
            SortingResponseControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_SORTING_RESPONSE),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::enumerated(0),
                    Asn1::octetString('cn')
                )))
            ))->setValue(null)
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_SORTING_RESPONSE),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::enumerated(0),
                    Asn1::context(0, Asn1::octetString('cn'))
                )))
            ),
            $this->subject->toAsn1(),
        );
    }
}
