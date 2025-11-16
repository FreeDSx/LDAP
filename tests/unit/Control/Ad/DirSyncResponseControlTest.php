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

namespace Tests\Unit\FreeDSx\Ldap\Control\Ad;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Ad\DirSyncResponseControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class DirSyncResponseControlTest extends TestCase
{
    private DirSyncResponseControl $subject;

    protected function setUp(): void
    {
        $this->subject = new DirSyncResponseControl(0);
    }

    public function test_it_should_get_the_more_results_value(): void
    {
        self::assertSame(
            0,
            $this->subject->getMoreResults()
        );
    }

    public function test_it_should_return_false_for_has_more_results_when_more_results_is_0(): void
    {
        self::assertFalse($this->subject->hasMoreResults());
    }

    public function test_it_should_return_false_for_has_more_results_when_more_results_is_not_0(): void
    {
        $this->subject = new DirSyncResponseControl(1);

        self::assertTrue($this->subject->hasMoreResults());
    }

    public function test_it_should_get_the_cookie(): void
    {
        self::assertSame(
            '',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_get_the_unused_value(): void
    {
        self::assertSame(
            0,
            $this->subject->getUnused(),
        );
    }

    public function test_it_should_generate_correct_ASN1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_DIR_SYNC),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(0),
                    Asn1::integer(0),
                    Asn1::octetString('')
                )))
            ),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            (new DirSyncResponseControl(0)),
            DirSyncResponseControl::fromAsn1(Asn1::sequence(
                Asn1::octetString(Control::OID_DIR_SYNC),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::integer(0),
                    Asn1::integer(0),
                    Asn1::octetString('')
                ))),
            ))->setValue(null),
        );
    }
}
