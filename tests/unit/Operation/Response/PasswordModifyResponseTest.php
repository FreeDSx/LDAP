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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class PasswordModifyResponseTest extends TestCase
{
    private PasswordModifyResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new PasswordModifyResponse(
            new LdapResult(0, 'foo'),
            '12345',
        );
    }

    public function test_it_should_get_the_dn(): void
    {
        self::assertEquals(
            new Dn('foo'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_get_the_generated_password(): void
    {
        self::assertSame(
            '12345',
            $this->subject->getGeneratedPassword(),
        );
    }

    public function test_it_should_be_constructed_from_asn1_with_a_generated_password(): void
    {
        $encoder = new LdapEncoder();

        $this->subject = PasswordModifyResponse::fromAsn1(Asn1::application(24, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                . $encoder->encode(Asn1::octetString('ldap://bar'))
            ))->setIsConstructed(true)),
            Asn1::context(11, Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(0, Asn1::octetString('bleep-blorp'))
            )))),
        )));

        self::assertSame(
            'bleep-blorp',
            $this->subject->getGeneratedPassword(),
        );
        self::assertSame(
            0,
            $this->subject->getResultCode(),
        );
        self::assertEquals(
            new Dn('dc=foo,dc=bar'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_be_constructed_from_asn1_without_a_generated_password(): void
    {
        $encoder = new LdapEncoder();

        $this->subject = PasswordModifyResponse::fromAsn1(Asn1::application(24, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                . $encoder->encode(Asn1::octetString('ldap://bar'))
            ))->setIsConstructed(true)),
            Asn1::context(11, Asn1::octetString($encoder->encode(Asn1::sequence()))),
        )));

        self::assertNull($this->subject->getGeneratedPassword());;
    }
}
