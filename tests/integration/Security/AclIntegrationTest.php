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
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\LdapAclCommand;

/**
 * End-to-end tests for RuleBasedAccessControl.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class AclIntegrationTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-acl',
            'tcp',
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-acl');
        parent::setUp();
    }

    public function testAnonymousSearchIsDenied(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
    }

    public function testAuthenticatedUserCanSearch(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertCount(1, $entries);
    }

    public function testAuthenticatedUserCanCompare(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $result = $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Smith',
        );

        self::assertTrue($result);
    }

    public function testAuthenticatedUserAddIsDenied(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=denied-add,dc=foo,dc=bar',
            ['cn' => 'denied-add', 'sn' => 'Denied', 'objectClass' => 'inetOrgPerson'],
        ));
    }

    public function testAuthenticatedUserDeleteIsDenied(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->delete('cn=alice,ou=people,dc=foo,dc=bar');
    }

    public function testAuthenticatedUserModifyDnIsDenied(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->rename(
            'cn=user,dc=foo,dc=bar',
            'cn=user-renamed',
            true,
        );
    }

    public function testUserCanModifyOwnEntry(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $entry = Entry::fromArray('cn=user,dc=foo,dc=bar');
        $entry->set('sn', 'UpdatedUser');
        $this->ldapClient()->update($entry);

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'UpdatedUser'))
                ->base('cn=user,dc=foo,dc=bar')
                ->useBaseScope(),
        );

        self::assertCount(1, $results);
    }

    public function testUserCannotModifyOtherEntry(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $entry = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $entry->set('sn', 'ShouldNotWork');
        $this->ldapClient()->update($entry);
    }

    public function testGroupMemberCanAddEntry(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=acl-temp-add,dc=foo,dc=bar',
            ['cn' => 'acl-temp-add', 'sn' => 'Temp', 'objectClass' => 'inetOrgPerson'],
        ));

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'acl-temp-add'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $results);

        $this->ldapClient()->delete('cn=acl-temp-add,dc=foo,dc=bar');
    }

    public function testGroupMemberCanDeleteEntry(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=acl-temp-delete,dc=foo,dc=bar',
            ['cn' => 'acl-temp-delete', 'sn' => 'Temp', 'objectClass' => 'inetOrgPerson'],
        ));

        $this->ldapClient()->delete('cn=acl-temp-delete,dc=foo,dc=bar');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'acl-temp-delete'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(0, $results);
    }

    public function testGroupMemberCanModifyAnyEntry(): void
    {
        $this->authenticateAdmin();

        $entry = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $entry->set('sn', 'AdminModified');
        $this->ldapClient()->update($entry);

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'AdminModified'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $results);

        $revert = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $revert->set('sn', 'Smith');
        $this->ldapClient()->update($revert);
    }

    public function testUserCannotWriteAnotherEntryPwdReset(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $entry = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $entry->set('pwdReset', 'TRUE');
        $this->ldapClient()->update($entry);
    }

    public function testAdminCanWriteAnotherEntryPwdReset(): void
    {
        $this->authenticateAdmin();

        $entry = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $entry->set('pwdReset', 'TRUE');
        $this->ldapClient()->update($entry);

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope()
                ->select('pwdReset'),
        );

        self::assertSame(
            ['TRUE'],
            $results->first()?->get('pwdReset')?->getValues(),
        );

        $revert = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $revert->reset('pwdReset');
        $this->ldapClient()->update($revert);
    }

    public function testUserCanRenameWithinAllowedSubtree(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->rename(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'cn=alice-renamed',
            true,
        );

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice-renamed'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $results);

        $this->ldapClient()->rename(
            'cn=alice-renamed,ou=people,dc=foo,dc=bar',
            'cn=alice',
            true,
        );
    }

    public function testRenameIsRefusedWhenTheDestinationDnIsDenied(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->rename(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'cn=reserved',
            true,
        );
    }

    public function testRenameCannotWriteAnRdnAttributeWithoutAGrant(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        // The rename itself is permitted over ou=people, but only cn is writable there.
        $this->ldapClient()->rename(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'uid=alice-uid',
            true,
        );
    }

    public function testRenameLeavesTheEntryUntouchedWhenTheRdnAttributeIsDenied(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        try {
            $this->ldapClient()->rename(
                'cn=alice,ou=people,dc=foo,dc=bar',
                'uid=alice-uid',
                true,
            );
        } catch (OperationException) {
        }

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $results);
        self::assertNull($results->first()?->get('uid'));
    }

    public function testRenameDeletingTheOldRdnRequiresAWriteOfThatAttributeToo(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        // cn is writable here, but dropping the old RDN would delete a uid value that is not.
        $this->ldapClient()->rename(
            'uid=bob,ou=people,dc=foo,dc=bar',
            'cn=bob-renamed',
            true,
        );
    }

    public function testTheSameRenameIsAllowedWhenTheOldRdnIsKept(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->rename(
            'uid=bob2,ou=people,dc=foo,dc=bar',
            'cn=bob2-renamed',
            false,
        );

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'bob2-renamed'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $results);
    }

    public function testRenameCannotUseAnAttributeOptionToEvadeAWriteDeny(): void
    {
        $this->bindDelegate();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->rename(
            'uid=bob,ou=people,dc=foo,dc=bar',
            new Rdn('userPassword;x', 'hunter2'),
            false,
        );
    }

    public function testAnEvadedRenameLeavesNoCredentialOnAPasswordlessEntry(): void
    {
        $this->bindDelegate();

        try {
            $this->ldapClient()->rename(
                'uid=bob,ou=people,dc=foo,dc=bar',
                new Rdn('userPassword;x', 'hunter2'),
                false,
            );
        } catch (OperationException) {
        }

        $this->authenticateAdmin();
        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('uid', 'bob'))
                ->base('ou=people,dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(1, $results);
        self::assertNull($results->first()?->get('userPassword'));
    }

    public function testRenameAuthorizesEveryComponentOfAMultivaluedRdn(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        // cn alone is writable, so pairing it with uid must not smuggle the second component through.
        $this->ldapClient()->rename(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'cn=alice-multi+uid=alice-multi',
            false,
        );
    }

    public function testUserCannotMoveEntryToRestrictedParent(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->move(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'dc=foo,dc=bar',
        );
    }

    public function testUserPasswordHiddenFromOtherUsers(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'sn', 'userPassword'),
        );

        $alice = $results->first();
        self::assertNotNull($alice);
        self::assertNull($alice->get('userPassword'));
    }

    public function testUserPasswordHiddenFromSelf(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'user'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'userPassword'),
        );

        $user = $results->first();
        self::assertNotNull($user);
        self::assertNull($user->get('userPassword'));
    }

    public function testUserPasswordVisibleToGroupMember(): void
    {
        $this->authenticateAdmin();

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'userPassword'),
        );

        $alice = $results->first();
        self::assertNotNull($alice);
        self::assertNotNull($alice->get('userPassword'));
    }

    public function testFilteringOnAnotherUsersPasswordMatchesNothing(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        // Confirming a guessed value must not be possible when the value cannot be read.
        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('userPassword', self::alicePasswordHash()))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            0,
            $results,
        );
    }

    public function testFilteringOnAPasswordPrefixMatchesNothing(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        // Substrings would otherwise recover the value one character at a time.
        $results = $this->ldapClient()->search(
            Operations::search(Filters::startsWith('userPassword', substr(self::alicePasswordHash(), 0, 6)))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            0,
            $results,
        );
    }

    public function testFilteringOnAPasswordMatchesForAGrantedSubject(): void
    {
        $this->authenticateAdmin();

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('userPassword', self::alicePasswordHash()))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            1,
            $results,
        );
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $results->first()?->getDn()->toString(),
        );
    }

    public function testADisjunctionKeepsTheBranchThatIsNotWithheld(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::or(
                Filters::equal('cn', 'alice'),
                Filters::equal('userPassword', self::alicePasswordHash()),
            ))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            1,
            $results,
        );
    }

    public function testComparingAConfidentialAttributeIsFalse(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        // No attribute rule denies secretCode, so this reaches the confidential gate rather than an access error.
        self::assertFalse($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'secretCode',
            LdapAclCommand::SECRET_CODE,
        ));
    }

    public function testComparingAnotherUsersPasswordIsDenied(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'userPassword',
            self::alicePasswordHash(),
        );
    }

    public function testACustomConfidentialAttributeIsHiddenWithoutAGrant(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'secretCode'),
        );

        $alice = $results->first();
        self::assertNotNull($alice);
        self::assertNull($alice->get('secretCode'));
    }

    public function testFilteringOnACustomConfidentialAttributeMatchesNothing(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('secretCode', LdapAclCommand::SECRET_CODE))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            0,
            $results,
        );
    }

    public function testAGrantDoesNotExtendToOtherConfidentialAttributes(): void
    {
        $this->authenticateAdmin();

        // The group is granted userPassword by name, which must not carry over to secretCode.
        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'secretCode'),
        );

        $alice = $results->first();
        self::assertNotNull($alice);
        self::assertNull($alice->get('secretCode'));
    }

    public function testAnAssertionCannotProbeAnEntryTheIdentityCannotSearch(): void
    {
        $this->bindHidden();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->send(
            Operations::modify(
                LdapAclCommand::HIDDEN_DN,
                Change::replace(
                    'description',
                    'asserted',
                ),
            ),
            Controls::assertion(Filters::equal(
                'sn',
                'Hidden',
            )),
        );
    }

    public function testTheSameModifySucceedsWithoutTheAssertion(): void
    {
        $this->bindHidden();

        $this->ldapClient()->send(Operations::modify(
            LdapAclCommand::HIDDEN_DN,
            Change::replace(
                'description',
                'unasserted',
            ),
        ));

        $this->authenticateAdmin();
        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'hidden'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            'unasserted',
            $results->first()?->get('description')?->firstValue(),
        );
    }

    public function testAnAdministratorCanStillAssertOnTheSameEntry(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->send(
            Operations::modify(
                LdapAclCommand::HIDDEN_DN,
                Change::replace(
                    'description',
                    'admin-asserted',
                ),
            ),
            Controls::assertion(Filters::equal(
                'sn',
                'Hidden',
            )),
        );

        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'hidden'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertSame(
            'admin-asserted',
            $results->first()?->get('description')?->firstValue(),
        );
    }

    public function testANonCriticalPreReadOnAnUnreadableTargetIsOmittedAndTheWriteStands(): void
    {
        $this->bindHidden();

        $response = $this->ldapClient()->send(
            Operations::modify(
                LdapAclCommand::HIDDEN_DN,
                Change::replace(
                    'description',
                    'preread-probe',
                ),
            ),
            Controls::preRead(),
        );

        self::assertNull($response?->controls()->get(Control::OID_PRE_READ));

        $this->authenticateAdmin();
        $results = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'hidden'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertSame(
            'preread-probe',
            $results->first()?->get('description')?->firstValue(),
        );
    }

    public function testACriticalPreReadOnAnUnreadableTargetFailsTheOperation(): void
    {
        $this->bindHidden();
        $preRead = Controls::preRead();
        $preRead->setCriticality(true);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->send(
            Operations::modify(
                LdapAclCommand::HIDDEN_DN,
                Change::replace(
                    'description',
                    'preread-critical',
                ),
            ),
            $preRead,
        );
    }

    public function testPreReadIsPermittedForAnIdentityThatCanSearchTheTarget(): void
    {
        $this->authenticateAdmin();

        $response = $this->ldapClient()->send(
            Operations::modify(
                LdapAclCommand::HIDDEN_DN,
                Change::replace(
                    'description',
                    'admin-preread',
                ),
            ),
            Controls::preRead('cn'),
        );

        $preRead = $response?->controls()->get(Control::OID_PRE_READ);
        self::assertInstanceOf(
            PreReadResponseControl::class,
            $preRead,
        );
        self::assertSame(
            ['hidden'],
            $preRead->getEntry()->get('cn')?->getValues(),
        );
    }

    public function testPasswordModifyDoesNotRevealWhetherAForbiddenTargetExists(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $missing = $this->passwordModifyCodeFor('cn=ghost,ou=people,dc=foo,dc=bar');
        $existing = $this->passwordModifyCodeFor('cn=alice,ou=people,dc=foo,dc=bar');

        self::assertSame(
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            $missing,
        );
        self::assertSame(
            $existing,
            $missing,
            'A forbidden target must answer the same whether or not it exists.',
        );
    }

    public function testPasswordModifyStillReportsAMissingTargetToAnAuthorizedIdentity(): void
    {
        $this->authenticateAdmin();

        self::assertSame(
            ResultCode::NO_SUCH_OBJECT,
            $this->passwordModifyCodeFor('cn=ghost,ou=people,dc=foo,dc=bar'),
        );
    }

    private function passwordModifyCodeFor(string $dn): int
    {
        try {
            $this->ldapClient()->send(Operations::passwordModify(
                $dn,
                'irrelevant',
                'newpass123',
            ));
        } catch (OperationException $e) {
            return $e->getCode();
        }

        self::fail('Expected an OperationException was not thrown.');
    }

    private function bindDelegate(): void
    {
        $this->ldapClient()->bind(
            LdapAclCommand::DELEGATE_DN,
            LdapAclCommand::DELEGATE_PASSWORD,
        );
    }

    private function bindHidden(): void
    {
        $this->ldapClient()->bind(
            LdapAclCommand::HIDDEN_DN,
            LdapAclCommand::HIDDEN_PASSWORD,
        );
    }

    private static function alicePasswordHash(): string
    {
        return '{SHA}' . base64_encode(sha1('alicepass', true));
    }
}
