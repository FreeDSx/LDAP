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
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

final class LdapPasswordPolicyServerTest extends ServerTestCase
{
    private const PASSWORD = '12345';

    private const WRONG_PASSWORD = 'nope';

    /**
     * The pwdMaxFailure the subentry seed configures.
     */
    private const MAX_FAILURE = 2;

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

    public function testACriticalPasswordPolicyControlIsAcceptedOnANonBindOperation(): void
    {
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            self::PASSWORD,
        );

        // The control may accompany any request, so a critical one must not be refused outside the bind.
        $response = $this->ldapClient()->sendAndReceive(
            Operations::whoami(),
            Controls::pwdPolicy(),
        )->getResponse();

        $this->assertInstanceOf(
            ExtendedResponse::class,
            $response,
        );
        $this->assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $response->getValue(),
        );
    }

    public function testACriticalPasswordPolicyControlIsAcceptedOnASearch(): void
    {
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            self::PASSWORD,
        );

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
            Controls::pwdPolicy(),
        );

        $this->assertGreaterThan(
            0,
            $entries->count(),
        );
    }

    public function testAUserGovernedByAPolicySubentryIsLockedOut(): void
    {
        $this->useSubentryPolicyServer();
        $dn = 'cn=inside-user,ou=secure,dc=foo,dc=bar';
        $this->failBinds($dn, self::MAX_FAILURE);

        $this->expectException(BindException::class);

        $this->ldapClient()->bind($dn, self::PASSWORD);
    }

    public function testAUserOutsideAnyAdministrativePointIsNotGoverned(): void
    {
        $this->useSubentryPolicyServer();
        $dn = 'cn=outside-user,dc=foo,dc=bar';
        $this->failBinds($dn, self::MAX_FAILURE + 1);

        $this->ldapClient()->bind($dn, self::PASSWORD);

        $this->assertSame(
            'dn:' . $dn,
            $this->ldapClient()->whoami(),
        );
    }

    /**
     * The specification chops ou=exempt, so the policy does not reach entries beneath it.
     */
    public function testABranchChoppedFromTheSpecificationIsNotGoverned(): void
    {
        $this->useSubentryPolicyServer();
        $dn = 'cn=exempt-user,ou=exempt,ou=secure,dc=foo,dc=bar';
        $this->failBinds($dn, self::MAX_FAILURE + 1);

        $this->ldapClient()->bind($dn, self::PASSWORD);

        $this->assertSame(
            'dn:' . $dn,
            $this->ldapClient()->whoami(),
        );
    }

    /**
     * Its pwdPolicySubentry names a policy with lockout disabled, which outranks the governing subentry.
     */
    public function testAnExplicitPointerOutranksTheGoverningSubentry(): void
    {
        $this->useSubentryPolicyServer();
        $dn = 'cn=pointer-user,ou=secure,dc=foo,dc=bar';
        $this->failBinds($dn, self::MAX_FAILURE + 1);

        $this->ldapClient()->bind($dn, self::PASSWORD);

        $this->assertSame(
            'dn:' . $dn,
            $this->ldapClient()->whoami(),
        );
    }

    /**
     * No policy is configured in PHP for this run, so enforcement can only come from the DIT.
     */
    private function useSubentryPolicyServer(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            ['--subentry-policy'],
        );
    }

    private function failBinds(
        string $dn,
        int $times,
    ): void {
        for ($i = 0; $i < $times; $i++) {
            try {
                $this->ldapClient()->bind($dn, self::WRONG_PASSWORD);

                self::fail('A bind with the wrong password should not succeed.');
            } catch (BindException) {
                // Expected: the point is to accumulate failures.
            }
        }
    }
}
