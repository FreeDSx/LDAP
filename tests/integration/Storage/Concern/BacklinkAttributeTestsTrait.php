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
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;

/**
 * The attribute whose values are the entries naming this one.
 */
trait BacklinkAttributeTestsTrait
{
    public function testTheGroupsAnEntryBelongsToAreReadBack(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-read');

        self::assertSame(
            [$group],
            $this->memberOfValues($member),
        );
    }

    public function testAnEntryInNoGroupHasNoBacklink(): void
    {
        $member = $this->seedBacklinkMember('backlink-loner');

        self::assertSame(
            [],
            $this->memberOfValues($member),
        );
    }

    public function testEveryGroupAnEntryBelongsToIsReadBack(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-several');
        $second = $this->seedBacklinkGroup('backlink-several-second', $member);

        self::assertEqualsCanonicalizing(
            [$group, $second],
            $this->memberOfValues($member),
        );
    }

    public function testASliceOfTheGroupsAnEntryBelongsToIsNamedForWhereItStops(): void
    {
        [$member] = $this->seedBacklinkPair('backlink-slice');
        $this->seedBacklinkGroup('backlink-slice-second', $member);
        $this->seedBacklinkGroup('backlink-slice-third', $member);

        $entry = $this->ldapClient()->read($member, ['memberOf;range=1-2']);

        self::assertSame(
            ['memberof;range=1-*'],
            $this->backlinkNamesOf($entry),
        );
        self::assertCount(
            2,
            $entry?->get('memberof;range=1-*')?->getValues() ?? [],
        );
    }

    public function testARangeOnABacklinkThatCannotBeServedIsRefused(): void
    {
        [$member] = $this->seedBacklinkPair('backlink-bad-range');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->ldapClient()->read($member, ['memberOf;range=9-2']);
    }

    public function testRemovingAMemberRemovesTheBacklink(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-removed');

        $this->ldapClient()->send(Operations::modify(
            $group,
            Change::delete('member', $member),
        ));

        self::assertSame(
            [],
            $this->memberOfValues($member),
        );
    }

    public function testDeletingTheGroupRemovesTheBacklink(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-deleted');

        $this->ldapClient()->delete($group);

        self::assertSame(
            [],
            $this->memberOfValues($member),
        );
    }

    public function testABacklinkIsNotReturnedWithTheUserWildcard(): void
    {
        [$member] = $this->seedBacklinkPair('backlink-wildcard');

        self::assertNull(
            $this->ldapClient()
                ->read($member, ['*'])
                ?->get('memberOf'),
        );
    }

    public function testABacklinkIsReturnedWithTheOperationalWildcard(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-operational');

        $entry = $this->ldapClient()->read($member, ['+']);

        self::assertSame(
            [$group],
            array_values($entry?->get('memberOf')?->getValues() ?? []),
        );
    }

    public function testASearchFindsTheMembersOfAGroup(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-filter');

        self::assertSame(
            [$member],
            $this->searchDns(Filters::equal('memberOf', $group)),
        );
    }

    public function testASearchFindsTheMembersOfAGroupHoweverTheDnIsSpelled(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-spelling');

        self::assertSame(
            [$member],
            $this->searchDns(Filters::equal('memberOf', strtoupper($group))),
        );
    }

    public function testABaseScopeSearchMatchesOnABacklinkItDidNotAskFor(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-base');

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('memberOf', $group), 'cn')
                ->base($member)
                ->useBaseScope(),
        );

        self::assertCount(1, $entries);
    }

    public function testABaseScopeSearchDoesNotMatchAGroupTheEntryIsNotIn(): void
    {
        [$member] = $this->seedBacklinkPair('backlink-base-miss');

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('memberOf', 'cn=nobody,dc=foo,dc=bar'), 'cn')
                ->base($member)
                ->useBaseScope(),
        );

        self::assertCount(0, $entries);
    }

    public function testComparingABacklinkIsTrueForAGroupTheEntryBelongsTo(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-compare');

        self::assertTrue(
            $this->ldapClient()->compare($member, 'memberOf', $group),
        );
    }

    public function testComparingABacklinkIsFalseForAGroupTheEntryDoesNotBelongTo(): void
    {
        [$member] = $this->seedBacklinkPair('backlink-compare-miss');

        self::assertFalse(
            $this->ldapClient()->compare($member, 'memberOf', 'cn=nobody,dc=foo,dc=bar'),
        );
    }

    public function testABacklinkNarrowsAConjunctionWithAStoredAttribute(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-and');

        self::assertSame(
            [$member],
            $this->searchDns(Filters::and(
                Filters::equal('cn', 'backlink-and'),
                Filters::equal('memberOf', $group),
            )),
        );
    }

    public function testAConjunctionExcludesAnEntryThatIsNotInTheGroup(): void
    {
        $this->seedBacklinkPair('backlink-and-miss');

        self::assertSame(
            [],
            $this->searchDns(Filters::and(
                Filters::equal('cn', 'backlink-and-miss'),
                Filters::equal('memberOf', 'cn=nobody,dc=foo,dc=bar'),
            )),
        );
    }

    public function testAConjunctionExcludesAMemberTheStoredAttributeDoesNotMatch(): void
    {
        [, $group] = $this->seedBacklinkPair('backlink-and-other');

        self::assertSame(
            [],
            $this->searchDns(Filters::and(
                Filters::equal('cn', 'someone-else'),
                Filters::equal('memberOf', $group),
            )),
        );
    }

    public function testABacklinkWidensADisjunctionWithAStoredAttribute(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-or');
        $other = $this->seedBacklinkMember('backlink-or-other');

        self::assertEqualsCanonicalizing(
            [$member, $other],
            $this->searchDns(Filters::or(
                Filters::equal('cn', 'backlink-or-other'),
                Filters::equal('memberOf', $group),
            )),
        );
    }

    public function testANegatedBacklinkExcludesTheMembersOfTheGroup(): void
    {
        [$member, $group] = $this->seedBacklinkPair('backlink-not');
        $other = $this->seedBacklinkMember('backlink-not-other');

        $found = $this->searchDns(Filters::and(
            Filters::or(
                Filters::equal('cn', 'backlink-not'),
                Filters::equal('cn', 'backlink-not-other'),
            ),
            Filters::not(Filters::equal('memberOf', $group)),
        ));

        self::assertNotContains($member, $found);
        self::assertContains($other, $found);
    }

    public function testASearchForAGroupThatHasNoMembersFindsNothing(): void
    {
        $this->authenticateAdmin();

        self::assertSame(
            [],
            $this->searchDns(Filters::equal('memberOf', 'cn=nobody,dc=foo,dc=bar')),
        );
    }

    public function testASearchForAnAssertionThatIsNotADistinguishedNameFindsNothing(): void
    {
        $this->authenticateAdmin();

        self::assertSame(
            [],
            $this->searchDns(Filters::equal('memberOf', 'not a dn')),
        );
    }

    public function testASearchFindsAnEntryBelongingToSomeGroup(): void
    {
        [$member] = $this->seedBacklinkPair('backlink-present');

        self::assertContains(
            $member,
            $this->searchDns(Filters::present('memberOf')),
        );
    }

    public function testASearchDoesNotFindAnEntryBelongingToNoGroup(): void
    {
        $member = $this->seedBacklinkMember('backlink-absent');

        self::assertNotContains(
            $member,
            $this->searchDns(Filters::present('memberOf')),
        );
    }

    public function testWritingABacklinkIsRefused(): void
    {
        $member = $this->seedBacklinkMember('backlink-written');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->send(Operations::modify(
            $member,
            Change::add('memberOf', 'cn=anything,dc=foo,dc=bar'),
        ));
    }

    public function testAddingAnEntryCarryingABacklinkIsRefused(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=backlink-refused,dc=foo,dc=bar',
            [
                'cn' => 'backlink-refused',
                'objectClass' => 'inetOrgPerson',
                'sn' => 'refused',
                'memberOf' => 'cn=anything,dc=foo,dc=bar',
            ],
        ));
    }

    /**
     * @return list<string>
     */
    private function searchDns(FilterInterface $filter): array
    {
        $found = [];
        $entries = $this->ldapClient()->search(
            Operations::search($filter, 'cn')
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        foreach ($entries as $entry) {
            $found[] = $entry->getDn()->toString();
        }

        return $found;
    }

    /**
     * @return list<string>
     */
    private function backlinkNamesOf(?Entry $entry): array
    {
        $names = [];

        foreach ($entry?->getAttributes() ?? [] as $attribute) {
            $names[] = $attribute->getDescription();
        }

        return $names;
    }

    /**
     * @return list<string>
     */
    private function memberOfValues(string $dn): array
    {
        return array_values(
            $this->ldapClient()
                ->read($dn, ['memberOf'])
                ?->get('memberOf')
                ?->getValues() ?? [],
        );
    }

    /**
     * A member and a group holding it, both of their own, since the server is shared across the class.
     *
     * @return array{string, string}
     */
    private function seedBacklinkPair(string $name): array
    {
        $member = $this->seedBacklinkMember($name);

        return [
            $member,
            $this->seedBacklinkGroup($name, $member),
        ];
    }

    private function seedBacklinkMember(string $name): string
    {
        $this->authenticateAdmin();
        $dn = "cn={$name},dc=foo,dc=bar";

        $this->ldapClient()->create(Entry::fromArray(
            $dn,
            [
                'cn' => $name,
                'objectClass' => 'inetOrgPerson',
                'sn' => $name,
            ],
        ));

        return $dn;
    }

    private function seedBacklinkGroup(
        string $name,
        string $member,
    ): string {
        $dn = "cn={$name}-group,dc=foo,dc=bar";

        $this->ldapClient()->create(Entry::fromArray(
            $dn,
            [
                'cn' => "{$name}-group",
                'objectClass' => 'groupOfNames',
                'member' => [$member],
            ],
        ));

        return $dn;
    }
}
