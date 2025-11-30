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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Response\SyncInfo;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class SyncNewCookieTest extends TestCase
{
    private SyncNewCookie $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncNewCookie('omnomnom');
    }

    public function test_it_should_get_the_cookie(): void
    {
        self::assertSame(
            'omnomnom',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_have_the_correct_response_name(): void
    {
        self::assertSame(
            IntermediateResponse::OID_SYNC_INFO,
            $this->subject->getName(),
        );
    }

    public function test_it_should_be_constructed_from_ASN1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            new SyncNewCookie('omnomnom'),
            SyncNewCookie::fromAsn1(Asn1::application(25, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(IntermediateResponse::OID_SYNC_INFO)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::context(0, Asn1::octetString('omnomnom')))))
            )))
        );
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::application(25, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(IntermediateResponse::OID_SYNC_INFO)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::context(0, Asn1::octetString('omnomnom')))))
            )),
            $this->subject->toAsn1(),
        );
    }
}
