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
use FreeDSx\Asn1\Type\EnumeratedType;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class SortingResponseControlTest extends TestCase
{
    protected SortingResponseControl $subject;

    protected function setUp(): void
    {
        $this->subject = new SortingResponseControl(
            result: 0,
            attribute: 'cn',
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
                    Asn1::octetString('cn'),
                ))),
            ))->setValue(null),
        );
    }

    public function test_a_result_wider_than_an_integer_is_refused_as_malformed(): void
    {
        $encoder = new LdapEncoder();

        $this->expectException(ProtocolException::class);
        $this->expectExceptionMessage('The server side sorting response result is not an integer.');

        SortingResponseControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SORTING_RESPONSE),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                new EnumeratedType('18446744073709551616'),
            ))),
        ));
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_SORTING_RESPONSE),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::enumerated(0),
                    Asn1::context(0, Asn1::octetString('cn')),
                ))),
            ),
            $this->subject->toAsn1(),
        );
    }
}
