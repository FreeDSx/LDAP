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
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\PlainOptions;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

final class LdapPasswordPolicySaslServerTest extends ServerTestCase
{
    public function setUp(): void
    {
        $this->setServerMode('ldap-password-policy');

        parent::setUp();

        $this->createServerProcess('tcp');
    }

    public function testSaslBindUnderResetCarriesThePasswordPolicyControl(): void
    {
        $response = $this->ldapClient()->bindSasl(
            (new PlainOptions())->setUsername('reset-user')->setPassword('12345'),
            MechanismName::PLAIN,
            controls: Controls::pwdPolicy(),
        );

        $control = $response->controls()->getByClass(PwdPolicyResponseControl::class);

        $this->assertInstanceOf(
            PwdPolicyResponseControl::class,
            $control,
            'A SASL bind under pwdReset should carry the password policy response control.',
        );
        $this->assertSame(
            PwdPolicyError::CHANGE_AFTER_RESET,
            $control->getError(),
        );
    }

    public function testCleanSaslBindCarriesNoControl(): void
    {
        $response = $this->ldapClient()->bindSasl(
            (new PlainOptions())->setUsername('user')->setPassword('12345'),
            MechanismName::PLAIN,
        );

        $this->assertFalse($response->controls()->has(Control::OID_PWD_POLICY));
    }
}
