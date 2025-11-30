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
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class BindResponseTest extends TestCase
{
    private BindResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new BindResponse(
            new LdapResult(
                0,
                'foo',
                'bar',
                new LdapUrl('foo')
            ),
            'foo',
        );
    }

    public function test_it_should_get_the_sasl_creds(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getSaslCredentials(),
        );
    }

    public function test_it_should_get_the_ldap_result_data(): void
    {
        self::assertSame(
            0,
            $this->subject->getResultCode(),
        );
        self::assertEquals(
            new Dn('foo'),
            $this->subject->getDn(),
        );
        self::assertSame(
            'bar',
            $this->subject->getDiagnosticMessage(),
        );
        self::assertEquals(
            [new LdapUrl('foo')],
            $this->subject->getReferrals(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $this->subject = BindResponse::fromAsn1(Asn1::application(1, Asn1::sequence(
            Asn1::enumerated(0),
            Asn1::octetString('dc=foo,dc=bar'),
            Asn1::octetString('foo'),
            Asn1::context(3, (new IncompleteType($encoder->encode(
                Asn1::octetString('ldap://foo')
            ))
            )->setIsConstructed(true)),
            Asn1::context(7, Asn1::octetString('foo'))
        )));

        self::assertSame(
            'foo',
            $this->subject->getSaslCredentials(),
        );
        self::assertSame(
            0,
            $this->subject->getResultCode(),
        );
        self::assertEquals(
            new Dn('dc=foo,dc=bar'),
            $this->subject->getDn(),
        );
        self::assertSame(
            'foo',
            $this->subject->getDiagnosticMessage(),
        );
        self::assertEquals(
            [new LdapUrl('foo')],
            $this->subject->getReferrals(),
        );
    }
}
