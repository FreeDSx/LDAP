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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Request;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use PHPUnit\Framework\TestCase;

final class ForwardPasswordPolicyStateRequestTest extends TestCase
{
    private const UUID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

    private DateTimeImmutable $time;

    private DateTimeImmutable $success;

    private ForwardPasswordPolicyStateRequest $subject;

    protected function setUp(): void
    {
        $this->time = new DateTimeImmutable(
            '2026-01-01 00:00:00',
            new DateTimeZone('UTC'),
        );
        $this->success = new DateTimeImmutable(
            '2026-01-02 00:00:00',
            new DateTimeZone('UTC'),
        );
        $this->subject = new ForwardPasswordPolicyStateRequest(
            self::UUID,
            [$this->time],
            $this->success,
        );
    }

    public function test_it_exposes_the_uuid_failure_times_and_last_success(): void
    {
        self::assertSame(
            self::UUID,
            $this->subject->getEntryUuid(),
        );
        self::assertEquals(
            [$this->time],
            $this->subject->getFailureTimes(),
        );
        self::assertEquals(
            $this->success,
            $this->subject->getLastSuccess(),
        );
    }

    public function test_last_success_defaults_to_null(): void
    {
        self::assertNull(
            (new ForwardPasswordPolicyStateRequest(self::UUID))->getLastSuccess(),
        );
    }

    public function test_it_uses_the_forward_oid(): void
    {
        self::assertSame(
            ExtendedRequest::OID_PPOLICY_STATE_FORWARD,
            $this->subject->getName(),
        );
    }

    public function test_it_generates_the_expected_asn1(): void
    {
        $encoder = new LdapEncoder();

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_PPOLICY_STATE_FORWARD)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::octetString(self::UUID),
                    Asn1::setOf(Asn1::octetString(GeneralizedTime::formatWithFraction($this->time))),
                    Asn1::context(0, Asn1::octetString(GeneralizedTime::format($this->success))),
                )))),
            )),
            $this->subject->toAsn1(),
        );
    }

    public function test_it_omits_last_success_from_asn1_when_absent(): void
    {
        $encoder = new LdapEncoder();
        $request = new ForwardPasswordPolicyStateRequest(
            self::UUID,
            [$this->time],
        );

        self::assertEquals(
            Asn1::application(23, Asn1::sequence(
                Asn1::context(0, Asn1::octetString(ExtendedRequest::OID_PPOLICY_STATE_FORWARD)),
                Asn1::context(1, Asn1::octetString($encoder->encode(Asn1::sequence(
                    Asn1::octetString(self::UUID),
                    Asn1::setOf(Asn1::octetString(GeneralizedTime::formatWithFraction($this->time))),
                )))),
            )),
            $request->toAsn1(),
        );
    }
}
