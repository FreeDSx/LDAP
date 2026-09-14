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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

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
}
