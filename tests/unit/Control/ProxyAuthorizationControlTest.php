<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ProxyAuthorizationControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdType;
use PHPUnit\Framework\TestCase;

final class ProxyAuthorizationControlTest extends TestCase
{
    public function test_it_defaults_to_an_empty_anonymous_authz_id(): void
    {
        $control = new ProxyAuthorizationControl(AuthzId::anonymous());

        self::assertSame('', $control->getRawAuthzId());
        self::assertTrue($control->getAuthzId()->isType(AuthzIdType::Anonymous));
    }

    public function test_it_exposes_the_authz_id(): void
    {
        $control = new ProxyAuthorizationControl(AuthzId::fromDn(new Dn('cn=foo,dc=example,dc=com')));

        self::assertSame(
            'dn:cn=foo,dc=example,dc=com',
            $control->getRawAuthzId(),
        );
        self::assertSame(
            'dn:cn=foo,dc=example,dc=com',
            $control->getAuthzId()->toString(),
        );
    }

    public function test_it_has_the_proxy_authorization_oid(): void
    {
        self::assertSame(
            Control::OID_PROXY_AUTHORIZATION,
            (new ProxyAuthorizationControl(AuthzId::anonymous()))->getTypeOid(),
        );
    }

    public function test_it_is_critical_by_default(): void
    {
        self::assertTrue((new ProxyAuthorizationControl(AuthzId::fromUsername('bob')))->getCriticality());
    }

    public function test_it_preserves_a_non_critical_flag_from_asn1(): void
    {
        $control = ProxyAuthorizationControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
            Asn1::boolean(false),
            Asn1::octetString('u:bob'),
        ));

        self::assertFalse($control->getCriticality());
    }

    public function test_it_generates_asn1_with_the_raw_authz_id_value(): void
    {
        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
                Asn1::boolean(true),
                Asn1::octetString('dn:cn=foo,dc=example,dc=com'),
            ),
            (new ProxyAuthorizationControl(AuthzId::fromDn(new Dn('cn=foo,dc=example,dc=com'))))->toAsn1(),
        );
    }

    public function test_it_generates_asn1_with_an_empty_value_for_anonymous(): void
    {
        self::assertEquals(
            Asn1::sequence(
                Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
                Asn1::boolean(true),
                Asn1::octetString(''),
            ),
            (new ProxyAuthorizationControl(AuthzId::anonymous()))->toAsn1(),
        );
    }

    public function test_it_is_constructed_from_asn1_reading_the_raw_value(): void
    {
        $control = ProxyAuthorizationControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
            Asn1::boolean(true),
            Asn1::octetString('u:bob'),
        ));

        self::assertSame(
            'u:bob',
            $control->getRawAuthzId(),
        );
        self::assertSame(
            'u:bob',
            $control->getAuthzId()->toString(),
        );
        self::assertTrue($control->getCriticality());
        self::assertSame(
            Control::OID_PROXY_AUTHORIZATION,
            $control->getTypeOid(),
        );
    }

    public function test_it_is_constructed_from_asn1_with_an_empty_value(): void
    {
        $control = ProxyAuthorizationControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
            Asn1::boolean(true),
            Asn1::octetString(''),
        ));

        self::assertSame(
            '',
            $control->getRawAuthzId(),
        );
    }

    public function test_it_refuses_a_control_without_a_value(): void
    {
        $this->expectException(ProtocolException::class);

        ProxyAuthorizationControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
            Asn1::boolean(true),
        ));
    }

    public function test_it_defers_a_malformed_authz_id_until_it_is_read(): void
    {
        $control = ProxyAuthorizationControl::fromAsn1(Asn1::sequence(
            Asn1::octetString(Control::OID_PROXY_AUTHORIZATION),
            Asn1::boolean(true),
            Asn1::octetString('mail:bob@example.com'),
        ));

        self::assertSame(
            'mail:bob@example.com',
            $control->getRawAuthzId(),
        );

        $this->expectException(InvalidArgumentException::class);

        $control->getAuthzId();
    }
}
