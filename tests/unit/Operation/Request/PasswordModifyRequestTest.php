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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Request;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class PasswordModifyRequestTest extends TestCase
{
    private PasswordModifyRequest $subject;

    protected function setUp(): void
    {
        $this->subject = new PasswordModifyRequest(
            'foo',
            'bar',
            '12345'
        );
    }

    public function test_it_should_get_the_new_password(): void
    {
        self::assertSame(
            '12345',
            $this->subject->getNewPassword(),
        );

        $this->subject->setNewPassword('foo');

        self::assertSame(
            'foo',
            $this->subject->getNewPassword(),
        );
    }

    public function test_it_should_get_the_old_password(): void
    {
        self::assertEquals(
            'bar',
            $this->subject->getOldPassword()
        );

        $this->subject->setOldPassword('foo');

        self::assertEquals(
            'foo',
            $this->subject->getOldPassword()
        );
    }

    public function test_it_should_get_the_username(): void
    {
        self::assertEquals(
            'foo',
            $this->subject->getUsername()
        );

        $this->subject->setUsername('bar');

        self::assertEquals(
            'bar',
            $this->subject->getUsername(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_PWD_MODIFY)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::context(0, Asn1::octetString('foo')),
                    Asn1::context(1, Asn1::octetString('bar')),
                    Asn1::context(2, Asn1::octetString('12345'))
                ))))
            )),
            $this->subject->toAsn1(),
        );

        $this->subject->setUsername(null);

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_PWD_MODIFY)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::context(1, Asn1::octetString('bar')),
                    Asn1::context(2, Asn1::octetString('12345'))
                ))))
            )),
            $this->subject->toAsn1(),
        );

        $this->subject->setOldPassword(null);

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_PWD_MODIFY)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::context(2, Asn1::octetString('12345'))
                ))))
            )),
            $this->subject->toAsn1(),
        );

        $this->subject->setNewPassword(null);

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_PWD_MODIFY)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence())))
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $passwdMod = new PasswordModifyRequest('foo', 'bar', '12345');
        $result = PasswordModifyRequest::fromAsn1($passwdMod->toAsn1());

        self::assertEquals(
            $passwdMod->setValue(null),
            $result->setValue(null),
        );

        $passwdMod = new PasswordModifyRequest(null, 'bar', '12345');
        $expected = PasswordModifyRequest::fromAsn1($passwdMod->toAsn1());
        self::assertEquals(
            $passwdMod->setValue(null),
            $expected->setValue(null),
        );

        $passwdMod = new PasswordModifyRequest('foo', null, '12345');
        $expected = PasswordModifyRequest::fromAsn1($passwdMod->toAsn1());
        self::assertEquals(
            $passwdMod->setValue(null),
            $expected->setValue(null),
        );
    }

    public function test_it_should_not_be_constructed_from_invalid_asn1(): void
    {
        $this->expectException(ProtocolException::class);

        PasswordModifyRequest::fromAsn1(
            (new ExtendedRequest('foo'))
                ->setValue(Asn1::set())
                ->toAsn1()
        );
    }
}
