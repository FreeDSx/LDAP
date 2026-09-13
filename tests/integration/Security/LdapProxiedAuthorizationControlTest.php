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

namespace Tests\Integration\FreeDSx\Ldap\Security;

use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * End-to-end RFC 4370 proxied authorization; the shared server grants cn=user the control for identities under ou=people.
 */
final class LdapProxiedAuthorizationControlTest extends ServerTestCase
{
    private const PROXIED_DN = 'cn=alice,ou=people,dc=foo,dc=bar';

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            ['--allow-proxy'],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    public function test_whoami_reports_the_proxied_identity(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $response = $this->ldapClient()->send(
            Operations::whoami(),
            Controls::proxyAuthorization(AuthzId::fromString('dn:' . self::PROXIED_DN)),
        );

        self::assertNotNull($response);
        $extended = $response->getResponse();
        self::assertInstanceOf(
            ExtendedResponse::class,
            $extended,
        );
        self::assertSame(
            'dn:' . self::PROXIED_DN,
            $extended->getValue(),
        );
    }

    public function test_a_proxied_identity_spelled_with_an_alias_resolves_to_the_entry(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $response = $this->ldapClient()->send(
            Operations::whoami(),
            Controls::proxyAuthorization(AuthzId::fromString('dn:commonName=alice,ou=people,dc=foo,dc=bar')),
        );

        self::assertNotNull($response);
        $extended = $response->getResponse();
        self::assertInstanceOf(
            ExtendedResponse::class,
            $extended,
        );
        self::assertSame(
            'dn:' . self::PROXIED_DN,
            $extended->getValue(),
        );
    }

    public function test_whoami_reports_the_bound_identity_without_the_control(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function test_a_proxied_search_runs_under_the_proxied_identity(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            Controls::proxyAuthorization(AuthzId::fromString('dn:' . self::PROXIED_DN)),
        );

        self::assertCount(1, $entries);
        self::assertSame(
            self::PROXIED_DN,
            (string) $entries->first()?->getDn(),
        );
    }

    public function test_proxy_is_denied_for_a_target_outside_the_permitted_subtree(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::AUTHORIZATION_DENIED);

        // dc=foo,dc=bar resolves but sits above ou=people, and is not the bound identity, so
        // neither the grant nor the authorize-as-self path applies.
        $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            Controls::proxyAuthorization(AuthzId::fromString('dn:dc=foo,dc=bar')),
        );
    }
}
