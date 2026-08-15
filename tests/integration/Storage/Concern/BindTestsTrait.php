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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;

/**
 * Authentication against the backend.
 */
trait BindTestsTrait
{
    public function testBindWithCorrectCredentials(): void
    {
        // No exception thrown — bind succeeded; verify the session is usable
        $this->authenticateUser();

        self::assertTrue(
            $this->ldapClient()->compare('cn=user,dc=foo,dc=bar', 'cn', 'user'),
        );
    }

    public function testBindWithWrongCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', 'wrongpassword');
    }

    public function testBindWithUnknownDn(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bind('cn=nobody,dc=foo,dc=bar', '12345');
    }

    public function testAnUnauthenticatedAbandonDrawsNoResponse(): void
    {
        self::assertNull($this->ldapClient()->send(Operations::abandon(99)));

        // A response to the abandon would be read here instead of the bind's own, so this proves none was sent.
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        self::assertTrue(
            $this->ldapClient()->compare('cn=user,dc=foo,dc=bar', 'cn', 'user'),
        );
    }

    public function testBindCarryingAnUnsupportedCriticalControlIsRefused(): void
    {
        try {
            $this->ldapClient()->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
                new Control('1.2.3.4.5', criticality: true),
            );
            self::fail('The unsupported critical control should have been refused.');
        } catch (BindException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                $e->getCode(),
            );
        }

        // The bind must not have taken effect, so the session is still anonymous.
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);
        $this->ldapClient()->compare('cn=user,dc=foo,dc=bar', 'cn', 'user');
    }

    public function testBindCarryingANonCriticalUnsupportedControlSucceeds(): void
    {
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
            new Control('1.2.3.4.5', criticality: false),
        );

        self::assertTrue(
            $this->ldapClient()->compare('cn=user,dc=foo,dc=bar', 'cn', 'user'),
        );
    }
}
