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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

final class LdapPasswordPolicyServerTest extends ServerTestCase
{
    private const ADMIN_DN = 'cn=admin,dc=foo,dc=bar';

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

    /**
     * draft-behera-11 §8.3 pairs changeAfterReset with insufficientAccessRights, not unwillingToPerform.
     */
    public function testAnOperationUnderResetIsRefusedWithInsufficientAccessRights(): void
    {
        $client = $this->ldapClient();
        $client->bind('cn=reset-user,dc=foo,dc=bar', self::PASSWORD);

        try {
            $client->search(
                Operations::search(Filters::equal('cn', 'reset-user'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                Controls::pwdPolicy(),
            );
            $this->fail('Expected the reset gate to refuse the search.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                $e->getCode(),
            );
        }
    }

    /**
     * draft-behera-11 §8.1.2.2 names StartTLS among the operations a pwdReset identity may still perform.
     */
    public function testStartTlsIsPermittedUnderResetSoTheIdentityCanComply(): void
    {
        $dn = 'cn=reset-user,dc=foo,dc=bar';
        $client = $this->ldapClient();
        $client->bind($dn, self::PASSWORD);

        $client->startTls();
        $client->send(Operations::passwordModify(
            $dn,
            self::PASSWORD,
            'a-fresh-password',
        ));

        // Binding with the new password proves StartTLS was permitted and the change it protects went through.
        $client->bind($dn, 'a-fresh-password');

        $this->assertSame(
            'dn:' . $dn,
            $client->whoami(),
        );
    }

    public function testAddingAnEntryWithAPasswordStampsItsPolicyState(): void
    {
        $dn = 'cn=added-user,dc=foo,dc=bar';
        $client = $this->ldapClient();
        $client->bind(self::ADMIN_DN, self::PASSWORD);

        $client->create(Entry::fromArray(
            $dn,
            [
                'objectClass' => ['inetOrgPerson'],
                'cn' => ['added-user'],
                'sn' => ['Added'],
                'userPassword' => [self::PASSWORD],
            ],
        ));

        $entry = $client->readOrFail(
            $dn,
            [PasswordPolicyOid::NAME_PWD_CHANGED_TIME],
        );

        $this->assertNotNull($entry->get(PasswordPolicyOid::NAME_PWD_CHANGED_TIME));
    }

    public function testAFractionalFailureTimestampIsMatchableByItsOwnValue(): void
    {
        $dn = 'cn=user,dc=foo,dc=bar';
        $this->failBinds($dn, 1);

        $client = $this->ldapClient();
        $client->bind(self::ADMIN_DN, self::PASSWORD);

        $recorded = $client->readOrFail(
            $dn,
            [PasswordPolicyOid::NAME_PWD_FAILURE_TIME],
        )->get(PasswordPolicyOid::NAME_PWD_FAILURE_TIME)?->firstValue();

        $this->assertIsString($recorded);
        $this->assertStringContainsString(
            '.',
            $recorded,
            'The server records these with a fraction to keep repeated failures distinct.',
        );

        $found = $client->search(
            Operations::search(
                Filters::equal(PasswordPolicyOid::NAME_PWD_FAILURE_TIME, $recorded),
            )
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $this->assertCount(
            1,
            $found,
            'A timestamp carrying a fraction must match the value the server itself wrote.',
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
