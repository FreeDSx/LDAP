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
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class SyncRequestControlTest extends TestCase
{
    private SyncRequestControl $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncRequestControl(
            mode: 1,
            cookie: 'omnomnom'
        );
    }

    public function test_it_should_get_the_mode(): void
    {
        self::assertSame(
            1,
            $this->subject->getMode(),
        );
    }

    public function test_it_should_get_the_reload_hint(): void
    {
        self::assertFalse($this->subject->getReloadHint());
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
                Asn1::octetString(Control::OID_SYNC_REQUEST),
                Asn1::boolean(true),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::enumerated(1),
                    Asn1::octetString('omnomnom'),
                    Asn1::boolean(false)
                )))
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $result = SyncRequestControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_SYNC_REQUEST),
            Asn1::boolean(true),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::enumerated(1),
                Asn1::octetString('omnomnom'),
                Asn1::boolean(false)
            )))
        ));


        self::assertSame(
            1,
            $result->getMode(),
        );
        self::assertSame(
            'omnomnom',
            $result->getCookie(),
        );
        self::assertSame(
            Control::OID_SYNC_REQUEST,
            $result->getTypeOid(),
        );
        self::assertFalse($result->getReloadHint());
    }
}
