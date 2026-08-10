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

use FreeDSx\Ldap\Exception\BindException;

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
}
