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

namespace Tests\Unit\FreeDSx\Ldap\Operation;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Asn1\Type\IncompleteType;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class LdapResultTest extends TestCase
{
    private LdapResult $subject;

    protected function setUp(): void
    {
        $this->subject = new LdapResult(
            0,
            'foo',
            'bar'
        );
    }

    public function test_it_should_get_the_diagnostic_message(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getDiagnosticMessage(),
        );
    }

    public function test_it_should_get_the_result_code(): void
    {
        self::assertSame(
            0,
            $this->subject->getResultCode(),
        );
    }

    public function test_it_should_get_the_dn(): void
    {
        self::assertEquals(
            new Dn('foo'),
            $this->subject->getDn(),
        );
    }

    public function test_it_should_get_the_referrals(): void
    {
        self::assertEmpty($this->subject->getReferrals());
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $this->subject = LdapResult::fromAsn1(Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                . $encoder->encode(Asn1::octetString('ldap://bar'))
            ))->setIsConstructed(true))
        ));

        self::assertEquals(
            new Dn('dc=foo,dc=bar'),
            $this->subject->getDn(),
        );
        self::assertSame(
            0,
            $this->subject->getResultCode(),
        );
        self::assertSame(
            'foo',
            $this->subject->getDiagnosticMessage(),
        );
        self::assertEquals(
            [
                new LdapUrl('foo'),
                new LdapUrl('bar'),
            ],
            $this->subject->getReferrals(),
        );
    }

    public function test_it_should_throw_a_protocol_exception_if_the_referral_cannot_be_parsed(): void
    {
        $encoder = new LdapEncoder();

        self::expectException(ProtocolException::class);

        LdapResult::fromAsn1(Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType(
                $encoder->encode(Asn1::octetString('ldap://foo'))
                . $encoder->encode(Asn1::octetString('bar'))
            ))->setIsConstructed(true))
        ));
    }
}
