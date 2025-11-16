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
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class SyncDoneControlTest extends TestCase
{
    private SyncDoneControl $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncDoneControl(
            cookie: 'omnomnom',
            refreshDeletes: false,
        );
    }

    public function test_it_should_get_refresh_deletes(): void
    {
        self::assertFalse($this->subject->getRefreshDeletes());
    }

    public function test_it_should_get_the_cookie(): void
    {
        self::assertSame(
            'omnomnom',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_SYNC_DONE),
                Asn1::boolean(true),
                Asn1::octetString(
                    $encoder->encode(Asn1::sequence(
                        Asn1::octetString('omnomnom'),
                        Asn1::boolean(false)
                    ))
                )
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $result = SyncDoneControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SYNC_DONE),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::octetString('omnomnom'),
                Asn1::boolean(false)
            )))
        ));

        self::assertFalse($result->getRefreshDeletes());
        self::assertSame(
            'omnomnom',
            $result->getCookie(),
        );
        self::assertSame(
            Control::OID_SYNC_DONE,
            $result->getTypeOid(),
        );
    }
}
