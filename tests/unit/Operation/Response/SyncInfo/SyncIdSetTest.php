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
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

final class SyncIdSetTest extends TestCase
{
    private SyncIdSet $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncIdSet(
            ['foo', 'bar'],
            false,
            'omnomnom',
        );
    }

    public function test_it_should_get_the_cookie(): void
    {
        self::assertSame(
            'omnomnom',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_get_whether_to_refresh_deletes(): void
    {
        self::assertFalse($this->subject->getRefreshDeletes());
    }

    public function test_it_should_get_the_entry_uuids(): void
    {
        self::assertSame(
            ['foo', 'bar'],
            $this->subject->getEntryUuids(),
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
            new SyncIdSet(
                ['foo', 'bar'],
                false,
                'omnomnom'
            ),
            SyncIdSet::fromAsn1(Asn1::application(25, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(IntermediateResponse::OID_SYNC_INFO)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::context(3, Asn1::sequence(
                    Asn1::octetString('omnomnom'),
                    Asn1::boolean(false),
                    Asn1::setOf(Asn1::octetString('foo'), Asn1::octetString('bar'))
                ))))),
            )))
        );
    }

    public function test_it_should_be_constructed_through_the_intermediate_response_factory_methd(): void
    {
        $encoder = new LdapEncoder();

        $result = IntermediateResponse::fromAsn1(Asn1::application(25, Asn1::sequence(
            Asn1::context(0, Asn1::octetString(IntermediateResponse::OID_SYNC_INFO)),
            Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::context(3, Asn1::sequence(
                Asn1::octetString('omnomnom'),
                Asn1::boolean(false),
                Asn1::setOf(Asn1::octetString('foo'), Asn1::octetString('bar'))
            )))))
        )));

        self::assertInstanceOf(
            SyncIdSet::class,
            $result,
        );
        self::assertSame(
            'omnomnom',
            $result->getCookie(),
        );
        self::assertFalse($result->getRefreshDeletes());
        self::assertSame(
            ['foo', 'bar'],
            $result->getEntryUuids(),
        );
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::application(25, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(IntermediateResponse::OID_SYNC_INFO)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::context(3, Asn1::sequence(
                    Asn1::octetString('omnomnom'),
                    Asn1::boolean(false),
                    Asn1::setOf(Asn1::octetString('foo'), Asn1::octetString('bar'))
                )))))
            )),
            $this->subject->toAsn1(),
        );
    }
}
