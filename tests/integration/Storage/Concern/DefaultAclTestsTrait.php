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
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Behavior enforced by the shipped default ACL, across the search, paging and write paths.
 */
trait DefaultAclTestsTrait
{
    public function testUserPasswordIsNotReturnedUnderTheDefaultAcl(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'user'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
                ->setAttributes('cn', 'userPassword'),
        );

        // The shipped default marks userPassword confidential and grants nobody access to it.
        $user = $entries->first();
        self::assertNotNull($user);
        self::assertNull($user->get('userPassword'));
    }

    public function testFilteringOnUserPasswordMatchesNothingUnderTheDefaultAcl(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('userPassword', '{SHA}' . base64_encode(sha1('12345', true))))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            0,
            $entries,
        );
    }

    #[DataProvider('passwordValueAttributeProvider')]
    public function testAnAttributeHoldingAPasswordValueIsNotReturnedToAnotherUser(string $attribute): void
    {
        $this->authenticateUser();

        $admin = $this->ldapClient()->read(
            'cn=admin,dc=foo,dc=bar',
            [
                $attribute,
                '*',
                '+',
            ],
        );

        self::assertNotNull($admin);
        self::assertNotNull($admin->get('cn'));
        self::assertNull($admin->get($attribute));
    }

    #[DataProvider('passwordValueAttributeProvider')]
    public function testFilteringOnAnAttributeHoldingAPasswordValueMatchesNothing(string $attribute): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present($attribute))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            0,
            $entries,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function passwordValueAttributeProvider(): iterable
    {
        yield 'userPassword' => ['userPassword'];
        yield 'pwdHistory' => [PasswordPolicyOid::NAME_PWD_HISTORY];
    }

    #[DataProvider('passwordPolicyStateAttributeProvider')]
    public function testAPasswordPolicyStateAttributeIsWithheldFromAnotherUser(string $attribute): void
    {
        $this->authenticateUser();

        $entry = $this->ldapClient()->read(
            'ou=people,dc=foo,dc=bar',
            [
                $attribute,
                '*',
                '+',
            ],
        );
        $matched = $this->ldapClient()->search(
            Operations::search(Filters::present($attribute))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertNotNull($entry);
        self::assertNull($entry->get($attribute));
        self::assertCount(
            0,
            $matched,
        );
    }

    #[DataProvider('passwordPolicyStateAttributeProvider')]
    public function testTheAdministratorReadsAndFiltersOnAPasswordPolicyStateAttribute(string $attribute): void
    {
        $this->authenticateAdmin();

        $entry = $this->ldapClient()->read(
            'ou=people,dc=foo,dc=bar',
            [$attribute],
        );
        $matched = $this->ldapClient()->search(
            Operations::search(
                Filters::present($attribute),
                '1.1',
            )
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertNotNull($entry?->get($attribute));
        self::assertContains(
            'ou=people,dc=foo,dc=bar',
            array_map(
                static fn(Entry $match): string => $match->getDn()->toString(),
                $matched->toArray(),
            ),
        );
    }

    public function testAnIdentityCannotReadItsOwnPasswordPolicyState(): void
    {
        $attributes = [
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
            PasswordPolicyOid::NAME_PWD_LAST_SUCCESS,
        ];
        $asAdministrator = $this->asAdmin(fn(LdapClient $admin): ?Entry => $admin->read(
            'cn=user,dc=foo,dc=bar',
            $attributes,
        ));

        $asSelf = $this->ldapClient()->read(
            'cn=user,dc=foo,dc=bar',
            [
                ...$attributes,
                '+',
            ],
        );

        self::assertNotNull($asSelf);
        foreach ($attributes as $attribute) {
            self::assertNotNull($asAdministrator?->get($attribute));
            self::assertNull($asSelf->get($attribute));
        }
    }

    #[DataProvider('storedPasswordPolicyStateProvider')]
    public function testTheAdministratorMatchesTheStoredPasswordPolicyState(
        string $attribute,
        string $dn,
        string $value,
    ): void {
        $this->authenticateAdmin();

        $matched = $this->ldapClient()->search(
            Operations::search(
                Filters::equal(
                    $attribute,
                    $value,
                ),
                '1.1',
            )
                ->base($dn)
                ->useBaseScope(),
        );

        self::assertCount(
            1,
            $matched,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function passwordPolicyStateAttributeProvider(): iterable
    {
        foreach (AclRules::PASSWORD_POLICY_STATE_ATTRIBUTES as $attribute) {
            yield $attribute => [$attribute];
        }
    }

    public function testNegatingAWithheldAssertionMatchesEveryEntry(): void
    {
        $this->authenticateUser();

        $all = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        // Withheld reads as absent, so negating it holds for every entry rather than none.
        $negated = $this->ldapClient()->search(
            Operations::search(Filters::not(Filters::equal('userPassword', 'anything')))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            count($all),
            $negated,
        );
    }

    #[DataProvider('storedWithheldValueProvider')]
    #[DataProvider('storedPasswordPolicyStateProvider')]
    public function testNegatingTheStoredValueOfAWithheldAttributeStillMatchesTheEntry(
        string $attribute,
        string $dn,
        string $value,
    ): void {
        $this->authenticateUser();

        $negated = $this->ldapClient()->search(
            Operations::search(
                Filters::not(Filters::equal(
                    $attribute,
                    $value,
                )),
                '1.1',
            )
                ->base($dn)
                ->useBaseScope(),
        );

        self::assertCount(
            1,
            $negated,
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function storedWithheldValueProvider(): iterable
    {
        yield 'userPassword' => [
            'userPassword',
            'cn=admin,dc=foo,dc=bar',
            '{SHA}jLIjfQZ5yojbZGTqxg2pY0VROWQ=',
        ];
        yield 'pwdHistory' => [
            PasswordPolicyOid::NAME_PWD_HISTORY,
            'cn=admin,dc=foo,dc=bar',
            '20260101000000Z#1.3.6.1.4.1.1466.115.121.1.40#6#old-pw',
        ];
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function storedPasswordPolicyStateProvider(): iterable
    {
        $stored = [
            PasswordPolicyOid::NAME_PWD_CHANGED_TIME => '20260101000000Z',
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME => '20260102000000Z',
            PasswordPolicyOid::NAME_PWD_FAILURE_TIME => '20260102000000.000001Z',
            PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME => '20260103000000.000001Z',
            PasswordPolicyOid::NAME_PWD_START_TIME => '20250101000000Z',
            PasswordPolicyOid::NAME_PWD_END_TIME => '20300101000000Z',
            PasswordPolicyOid::NAME_PWD_LAST_SUCCESS => '20260104000000Z',
            PasswordPolicyOid::NAME_PWD_RESET => 'TRUE',
            PasswordPolicyOid::NAME_PWD_POLICY_SUBENTRY => 'ou=people,dc=foo,dc=bar',
        ];

        foreach ($stored as $attribute => $value) {
            yield $attribute => [
                $attribute,
                'ou=people,dc=foo,dc=bar',
                $value,
            ];
        }
    }

    public function testAConjunctionWithAWithheldAssertionMatchesNothing(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::and(
                Filters::equal('cn', 'user'),
                Filters::equal('userPassword', 'anything'),
            ))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        self::assertCount(
            0,
            $entries,
        );
    }

    public function testPagingWithholdsConfidentialAttributes(): void
    {
        $this->authenticateUser();

        // Paging strips results on its own loop, separate from the one a plain search uses.
        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope()
            ->setAttributes('cn', 'userPassword');

        $paging = $this->ldapClient()->paging($search, 2);
        $withPassword = 0;

        while ($paging->hasEntries()) {
            foreach ($paging->getEntries() as $entry) {
                if ($entry->get('userPassword') !== null) {
                    $withPassword++;
                }
            }
        }

        self::assertSame(
            0,
            $withPassword,
        );
    }

    public function testPagingOnAWithheldFilterReturnsNothing(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::equal('userPassword', 'anything'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $paging = $this->ldapClient()->paging($search, 2);
        $found = 0;

        while ($paging->hasEntries()) {
            $found += count($paging->getEntries());
        }

        self::assertSame(
            0,
            $found,
        );
    }

    /**
     * @return iterable<string, array{FilterInterface}>
     */
    public static function filterMatchingNothingProvider(): iterable
    {
        yield 'a filter no entry matches' => [Filters::equal(
            'cn',
            'no-entry-has-this',
        )];
        yield 'the absolute false' => [Filters::or()];
        yield 'a filter on a withheld attribute' => [Filters::present('userPassword')];
    }

    #[DataProvider('filterMatchingNothingProvider')]
    public function testAFilterMatchingNothingStillAppliesTheBaseAndEveryControl(FilterInterface $filter): void
    {
        $this->authenticateUser();

        self::assertSame(
            [
                'missing base' => ResultCode::NO_SUCH_OBJECT,
                'false assertion' => ResultCode::ASSERTION_FAILED,
                'invented paging cookie' => ResultCode::UNWILLING_TO_PERFORM,
                'critical sort it cannot do' => ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            ],
            [
                'missing base' => $this->searchResultCode(
                    $filter,
                    'ou=nope,dc=foo,dc=bar',
                ),
                'false assertion' => $this->searchResultCode(
                    $filter,
                    'dc=foo,dc=bar',
                    Controls::assertion(Filters::equal(
                        'dc',
                        'no-entry-has-this',
                    )),
                ),
                'invented paging cookie' => $this->searchResultCode(
                    $filter,
                    'dc=foo,dc=bar',
                    Controls::paging(
                        5,
                        'invented',
                    ),
                ),
                'critical sort it cannot do' => $this->searchResultCode(
                    $filter,
                    'dc=foo,dc=bar',
                    Controls::sort('description')->setCriticality(true),
                ),
            ],
        );
    }

    #[DataProvider('filterMatchingNothingProvider')]
    public function testAFilterMatchingNothingStillRefusesARangeItCannotServe(FilterInterface $filter): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->ldapClient()->search(
            Operations::search(
                $filter,
                'cn;range=0-5',
            )
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
    }

    #[DataProvider('filterMatchingNothingProvider')]
    public function testAPagedFilterMatchingNothingEndsWithAnEmptyPagingCookie(FilterInterface $filter): void
    {
        $this->authenticateUser();

        $response = $this->ldapClient()->sendAndReceive(
            Operations::search($filter)
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
            Controls::paging(5),
        );
        $paging = $response->controls()->get(Control::OID_PAGING);

        self::assertInstanceOf(
            PagingControl::class,
            $paging,
        );
        self::assertSame(
            '',
            $paging->getCookie(),
        );
    }

    public function testAValueLevelModifyOfAWithheldAttributeOnAnotherEntryIsRefused(): void
    {
        $this->authenticateAdmin();
        // The admin may write userPassword but not read it, so a value assertion must not confirm a value.
        $dn = 'cn=vp-target,ou=people,dc=foo,dc=bar';
        $stored = '{SHA}' . base64_encode(sha1('known', true));
        $this->ldapClient()->create(Entry::fromArray($dn, [
            'objectClass' => ['inetOrgPerson'],
            'cn' => ['vp-target'],
            'sn' => ['ValueProbe'],
            'userPassword' => [$stored],
        ]));

        $addExisting = null;
        $deleteMissing = null;
        try {
            try {
                $this->ldapClient()->send(Operations::modify(
                    $dn,
                    Change::add('userPassword', $stored),
                ));
            } catch (OperationException $e) {
                $addExisting = $e->getCode();
            }
            try {
                $this->ldapClient()->send(Operations::modify(
                    $dn,
                    Change::delete('userPassword', '{SHA}bogusvaluenotpresent='),
                ));
            } catch (OperationException $e) {
                $deleteMissing = $e->getCode();
            }
            // A whole-attribute replace asserts nothing about the hidden value, so it must still succeed.
            $this->ldapClient()->send(Operations::modify(
                $dn,
                Change::replace('userPassword', '{SHA}' . base64_encode(sha1('reset', true))),
            ));
        } finally {
            $this->ldapClient()->delete($dn);
        }

        self::assertSame(
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            $addExisting,
        );
        self::assertSame(
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            $deleteMissing,
        );
    }

    public function testSelfMayMakeAValueLevelModifyOfItsOwnWithheldAttribute(): void
    {
        // cn=user can write but not read its own userPassword; a value assertion on its own entry is allowed
        // through to the ordinary value check rather than refused, so a self password change by delete-old works.
        $this->authenticateUser();

        $code = null;
        try {
            $this->ldapClient()->send(Operations::modify(
                'cn=user,dc=foo,dc=bar',
                Change::delete('userPassword', '{SHA}notthestoredvalue='),
            ));
        } catch (OperationException $e) {
            $code = $e->getCode();
        }

        self::assertSame(
            ResultCode::NO_SUCH_ATTRIBUTE,
            $code,
        );
    }

    private function searchResultCode(
        FilterInterface $filter,
        string $base,
        Control ...$controls,
    ): int {
        try {
            $this->ldapClient()->search(
                Operations::search($filter)
                    ->base($base)
                    ->useSubtreeScope(),
                ...$controls,
            );
        } catch (OperationException $e) {
            return $e->getCode();
        }

        return ResultCode::SUCCESS;
    }
}
