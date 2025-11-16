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

namespace Tests\Unit\FreeDSx\Ldap\Control\Sync;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class SyncStateControlTest extends TestCase
{
    private SyncStateControl $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncStateControl(
            state: 0,
            entryUuid: 'foo',
            cookie: 'omnomnom',
        );
    }

    public function test_it_should_get_the_state(): void
    {
        self::assertSame(
            0,
            $this->subject->getState(),
        );
    }

    public function test_it_should_get_the_entry_uuid(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getEntryUuid(),
        );
    }

    public function test_it_should_get_the_cookie(): void
    {
        self::assertSame(
            'omnomnom',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_tell_if_it_is_for_a_present_state(): void
    {
        $this->subject = new SyncStateControl(
            state: SyncStateControl::STATE_PRESENT,
            entryUuid: 'foo',
        );

        self::assertTrue($this->subject->isPresent());
    }

    public function test_it_should_tell_if_it_is_for_an_add_state(): void
    {
        $this->subject = new SyncStateControl(
            state: SyncStateControl::STATE_ADD,
            entryUuid: 'foo',
        );

        self::assertTrue($this->subject->isAdd());
    }

    public function test_it_should_tell_if_it_is_for_a_modify_state(): void
    {
        $this->subject = new SyncStateControl(
            state: SyncStateControl::STATE_MODIFY,
            entryUuid: 'foo',
        );

        self::assertTrue($this->subject->isModify());
    }

    public function test_it_should_tell_if_it_is_for_a_delete_state(): void
    {
        $this->subject = new SyncStateControl(
            state: SyncStateControl::STATE_DELETE,
            entryUuid: 'foo',
        );

        self::assertTrue($this->subject->isDelete());
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_SYNC_STATE),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::enumerated(0),
                    Asn1::octetString('foo'),
                    Asn1::octetString('omnomnom')
                )))
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $result = SyncStateControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SYNC_STATE),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::enumerated(0),
                Asn1::octetString('foo'),
                Asn1::octetString('omnomnom')
            )))
        ));

        self::assertSame(
            0,
            $result->getState(),
        );
        self::assertSame(
            'foo',
            $result->getEntryUuid(),
        );
        self::assertSame(
            'omnomnom',
            $result->getCookie(),
        );
        self::assertSame(
            Control::OID_SYNC_STATE,
            $result->getTypeOid(),
        );
    }
}
