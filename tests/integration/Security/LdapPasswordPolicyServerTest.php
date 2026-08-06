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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Control\PwdPolicyResponseControl;
use FreeDSx\Ldap\Controls;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

final class LdapPasswordPolicyServerTest extends ServerTestCase
{
    public function setUp(): void
    {
        $this->setServerMode('ldap-password-policy');

        parent::setUp();

        $this->createServerProcess('tcp');
    }

    public function testBindUnderResetCarriesThePasswordPolicyControl(): void
    {
        $response = $this->ldapClient()->bind(
            'cn=reset-user,dc=foo,dc=bar',
            '12345',
            Controls::pwdPolicy(),
        );

        $control = $response->controls()->getByClass(PwdPolicyResponseControl::class);

        $this->assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
            'A bind under pwdReset should carry the typed password policy response control.',
        );
        $this->assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $control->getError(),
        );
    }

    public function testBindWithoutPolicyStateCarriesNoControl(): void
    {
        $response = $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        $this->assertFalse(
            $response->controls()->has(Control::OID_PWD_POLICY),
            'A clean bind should not carry a password policy response control.',
        );
    }
}
