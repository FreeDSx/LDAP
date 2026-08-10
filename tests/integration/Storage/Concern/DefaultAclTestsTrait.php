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

use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Behavior enforced by the shipped default ACL, across the search and paging paths.
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
}
