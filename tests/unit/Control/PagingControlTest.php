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

namespace Tests\Unit\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class PagingControlTest extends TestCase
{
    private PagingControl $subject;

    protected function setUp(): void
    {
        $this->subject = new PagingControl(
            size: 0,
            cookie: 'foo',
        );
    }

    public function test_it_should_default_to_an_empty_cookie_on_construction(): void
    {
        $this->subject = new PagingControl(0);

        self::assertSame(
            '',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_set_the_size(): void
    {
        $this->subject->setSize(1);

        self::assertSame(
            1,
            $this->subject->getSize(),
        );
    }

    public function test_it_should_set_the_cookie(): void
    {
        $this->subject->setCookie('foo');

        self::assertSame(
            'foo',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PAGING),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(0),
                    Asn1::octetString('foo')
                )))
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $result = PagingControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_PAGING),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::integer(1),
                Asn1::octetString('foobar')
            )))
        ));

        self::assertSame(
            1,
            $result->getSize(),
        );
        self::assertSame(
            'foobar',
            $result->getCookie(),
        );
    }
}
