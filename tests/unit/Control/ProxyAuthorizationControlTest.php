<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Control;

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ProxyAuthorizationControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
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

    public function test_an_unparsed_authz_id_is_kept_raw_until_it_is_read(): void
    {
        $control = ProxyAuthorizationControl::unparsed(
            'mail:bob@example.com',
            false,
        );

        self::assertSame(
            ['mail:bob@example.com', false],
            [
                $control->getRawAuthzId(),
                $control->getCriticality(),
            ],
        );

        $this->expectException(InvalidArgumentException::class);

        $control->getAuthzId();
    }
}
