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

namespace Tests\Unit\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use PHPUnit\Framework\TestCase;

class PwdPolicyResponseControlTest extends TestCase
{
    private PwdPolicyResponseControl $subject;

    protected function setUp(): void
    {
        $this->subject = new PwdPolicyResponseControl(
            timeBeforeExpiration: 1,
            graceAuthRemaining: 2,
            error: 3,
        );
    }

    public function test_it_should_get_the_error(): void
    {
        self::assertSame(
            3,
            $this->subject->getError(),
        );
    }

    public function test_it_should_get_the_time_before_expiration(): void
    {
        self::assertSame(
            1,
            $this->subject->getTimeBeforeExpiration(),
        );
    }

    public function test_it_should_get_the_grace_attempts_remaining(): void
    {
        self::assertSame(
            2,
            $this->subject->getGraceAttemptsRemaining(),
        );
    }

    public function test_it_should_be_constructed_from_asn1(): void
    {
        $encoder = new LdapEncoder();

        $result = PwdPolicyResponseControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_PWD_POLICY),
            Asn1::boolean(false),
            Asn1::octetString($encoder->encode(Asn1::sequence(
                Asn1::context(0, Asn1::sequence(Asn1::context(0, Asn1::integer(100)))),
                Asn1::context(1, Asn1::enumerated(2))
            )))
        ));

        self::assertSame(
            100,
            $result->getTimeBeforeExpiration()
        );
        self::assertSame(
            2,
            $result->getError()
        );
        self::assertSame(
            Control::OID_PWD_POLICY,
            $result->getTypeOid()
        );
        self::assertFalse($result->getCriticality());
    }

    public function test_it_should_generate_correct_asn1(): void
    {
        $encoder = new LdapEncoder();

        $this->subject = new PwdPolicyResponseControl(
            timeBeforeExpiration: 100,
            graceAuthRemaining: null,
            error: 2,
        );

        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PWD_POLICY),
                Asn1::boolean(false),
                Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::context(0, Asn1::sequence(Asn1::context(0, Asn1::integer(100)))),
                    Asn1::context(1, Asn1::enumerated(2))
                )))
            ),
            $this->subject->toAsn1(),
        );
    }
}
