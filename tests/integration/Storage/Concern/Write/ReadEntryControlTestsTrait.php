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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PostReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadResponseControl;
use FreeDSx\Ldap\Control\ReadEntry\ReadEntryResponseControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PHPUnit\Framework\Attributes\DataProvider;

use function array_values;

/**
 * The pre-read and post-read controls (RFC 4527): the entry as a write found it and as it left it.
 */
trait ReadEntryControlTestsTrait
{
    public function testAPostReadMatchesTheEntryAsStoredAfterTheModify(): void
    {
        $this->authenticateAdmin();
        $dn = 'cn=post-read-modify,dc=foo,dc=bar';
        $this->ldapClient()->create(Entry::fromArray($dn, [
            'objectClass' => ['inetOrgPerson'],
            'cn' => ['post-read-modify'],
            'sn' => ['Before'],
        ]));

        $response = $this->ldapClient()->sendAndReceive(
            Operations::modify(
                $dn,
                Change::replace('sn', 'After'),
            ),
            Controls::postRead(),
        );
        $stored = $this->ldapClient()->read($dn);
        $this->ldapClient()->delete($dn);

        $postRead = $response->controls()->get(Control::OID_POST_READ);
        self::assertInstanceOf(
            PostReadResponseControl::class,
            $postRead,
        );
        self::assertEquals(
            $stored?->toArray(),
            $postRead->getEntry()->toArray(),
        );
    }

    public function testThePreReadAndPostReadOfAModifyDnCarryTheOldAndNewNames(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray('cn=before-rename,dc=foo,dc=bar', [
            'objectClass' => ['inetOrgPerson'],
            'cn' => ['before-rename'],
            'sn' => ['Renamed'],
        ]));

        $response = $this->ldapClient()->sendAndReceive(
            Operations::rename(
                'cn=before-rename,dc=foo,dc=bar',
                'cn=after-rename',
            ),
            Controls::preRead('cn'),
            Controls::postRead('cn'),
        );
        $this->ldapClient()->delete('cn=after-rename,dc=foo,dc=bar');

        $preRead = $response->controls()->get(Control::OID_PRE_READ);
        $postRead = $response->controls()->get(Control::OID_POST_READ);
        self::assertInstanceOf(
            PreReadResponseControl::class,
            $preRead,
        );
        self::assertInstanceOf(
            PostReadResponseControl::class,
            $postRead,
        );
        self::assertSame(
            'cn=before-rename,dc=foo,dc=bar',
            $preRead->getEntry()->getDn()->toString(),
        );
        self::assertSame(
            'cn=after-rename,dc=foo,dc=bar',
            $postRead->getEntry()->getDn()->toString(),
        );
        self::assertSame(
            ['after-rename'],
            $postRead->getEntry()->get('cn')?->getValues(),
        );
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function derivedAttributeSelections(): iterable
    {
        yield 'named' => [[
            'entryDN',
            'subschemaSubentry',
            'hasSubordinates',
        ]];
        yield 'operational wildcard' => [[
            '+',
        ]];
    }

    /**
     * @param list<string> $attributes
     */
    #[DataProvider('derivedAttributeSelections')]
    public function testAPostReadCarriesTheDerivedAttributesItSelects(array $attributes): void
    {
        $this->authenticateAdmin();
        $dn = 'cn=post-read-derived,dc=foo,dc=bar';
        $this->ldapClient()->create(Entry::fromArray($dn, [
            'objectClass' => ['inetOrgPerson'],
            'cn' => ['post-read-derived'],
            'sn' => ['Before'],
        ]));

        $response = $this->ldapClient()->sendAndReceive(
            Operations::modify(
                $dn,
                Change::replace('sn', 'After'),
            ),
            Controls::postRead(...$attributes),
        );
        $this->ldapClient()->delete($dn);

        $postRead = $response->controls()->get(Control::OID_POST_READ);
        self::assertInstanceOf(
            PostReadResponseControl::class,
            $postRead,
        );
        self::assertSame(
            [$dn],
            $postRead->getEntry()->get('entryDN')?->getValues(),
        );
        self::assertSame(
            ['cn=Subschema'],
            $postRead->getEntry()->get('subschemaSubentry')?->getValues(),
        );
        self::assertSame(
            ['FALSE'],
            $postRead->getEntry()->get('hasSubordinates')?->getValues(),
        );
    }

    public function testThePreReadAndPostReadOfARenamedParentReportItsSubordinates(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray('ou=before-parent,dc=foo,dc=bar', [
            'objectClass' => ['organizationalUnit'],
            'ou' => ['before-parent'],
        ]));
        $this->ldapClient()->create(Entry::fromArray('cn=child,ou=before-parent,dc=foo,dc=bar', [
            'objectClass' => ['inetOrgPerson'],
            'cn' => ['child'],
            'sn' => ['Child'],
        ]));

        $response = $this->ldapClient()->sendAndReceive(
            Operations::rename(
                'ou=before-parent,dc=foo,dc=bar',
                'ou=after-parent',
            ),
            Controls::preRead('hasSubordinates'),
            Controls::postRead('hasSubordinates'),
        );
        $this->ldapClient()->delete('cn=child,ou=after-parent,dc=foo,dc=bar');
        $this->ldapClient()->delete('ou=after-parent,dc=foo,dc=bar');

        $preRead = $response->controls()->get(Control::OID_PRE_READ);
        $postRead = $response->controls()->get(Control::OID_POST_READ);
        self::assertInstanceOf(
            PreReadResponseControl::class,
            $preRead,
        );
        self::assertInstanceOf(
            PostReadResponseControl::class,
            $postRead,
        );
        self::assertSame(
            ['TRUE'],
            $preRead->getEntry()->get('hasSubordinates')?->getValues(),
        );
        self::assertSame(
            ['TRUE'],
            $postRead->getEntry()->get('hasSubordinates')?->getValues(),
        );
    }

    public function testThePreReadOfASubtreeDeleteIsTheBaseWithItsSubordinates(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(Entry::fromArray('ou=pre-read-tree,dc=foo,dc=bar', [
            'objectClass' => ['organizationalUnit'],
            'ou' => ['pre-read-tree'],
        ]));
        $this->ldapClient()->create(Entry::fromArray('cn=child,ou=pre-read-tree,dc=foo,dc=bar', [
            'objectClass' => ['inetOrgPerson'],
            'cn' => ['child'],
            'sn' => ['Child'],
        ]));

        $response = $this->ldapClient()->sendAndReceive(
            Operations::delete('ou=pre-read-tree,dc=foo,dc=bar'),
            Controls::subtreeDelete(),
            Controls::preRead('ou', 'hasSubordinates'),
        );

        $preRead = $response->controls()->get(Control::OID_PRE_READ);
        self::assertInstanceOf(
            PreReadResponseControl::class,
            $preRead,
        );
        self::assertSame(
            ['pre-read-tree'],
            $preRead->getEntry()->get('ou')?->getValues(),
        );
        self::assertSame(
            ['TRUE'],
            $preRead->getEntry()->get('hasSubordinates')?->getValues(),
        );

        $this->authenticateUser();
        self::assertNull($this->ldapClient()->read('cn=child,ou=pre-read-tree,dc=foo,dc=bar'));
    }

    /**
     * @return iterable<string, array{list<string>}>
     */
    public static function backlinkSelections(): iterable
    {
        yield 'named' => [['memberOf']];
        yield 'operational wildcard' => [['+']];
    }

    /**
     * @param list<string> $attributes
     */
    #[DataProvider('backlinkSelections')]
    public function testThePreReadAndPostReadCarryTheBackLinksTheySelect(array $attributes): void
    {
        $this->authenticateAdmin();
        $member = 'cn=read-member,dc=foo,dc=bar';
        $group = 'cn=read-group,dc=foo,dc=bar';
        $this->ldapClient()->create(Entry::fromArray(
            $member,
            [
                'objectClass' => ['inetOrgPerson'],
                'cn' => ['read-member'],
                'sn' => ['Member'],
            ],
        ));
        $this->ldapClient()->create(Entry::fromArray(
            $group,
            [
                'objectClass' => ['groupOfNames'],
                'cn' => ['read-group'],
                'member' => [$member, 'cn=user,dc=foo,dc=bar'],
            ],
        ));

        $modify = $this->ldapClient()->sendAndReceive(
            Operations::modify(
                $member,
                Change::replace(
                    'sn',
                    'Changed',
                ),
            ),
            Controls::preRead(...$attributes),
            Controls::postRead(...$attributes),
        );
        $delete = $this->ldapClient()->sendAndReceive(
            Operations::delete($member),
            Controls::preRead(...$attributes),
        );
        $this->ldapClient()->delete($group);

        self::assertSame(
            [[$group], [$group], [$group]],
            [
                $this->readEntryValues(
                    $modify,
                    Control::OID_PRE_READ,
                    'memberOf',
                ),
                $this->readEntryValues(
                    $modify,
                    Control::OID_POST_READ,
                    'memberOf',
                ),
                $this->readEntryValues(
                    $delete,
                    Control::OID_PRE_READ,
                    'memberOf',
                ),
            ],
        );
    }

    public function testAPostReadCarriesTheBackLinkAWriteGivesItsOwnEntry(): void
    {
        $this->authenticateAdmin();
        $group = 'cn=read-self,dc=foo,dc=bar';

        $add = $this->ldapClient()->sendAndReceive(
            Operations::add(Entry::fromArray(
                $group,
                [
                    'objectClass' => ['groupOfNames'],
                    'cn' => ['read-self'],
                    'member' => [$group, 'cn=user,dc=foo,dc=bar'],
                ],
            )),
            Controls::postRead('memberOf'),
        );
        $modify = $this->ldapClient()->sendAndReceive(
            Operations::modify(
                $group,
                Change::delete(
                    'member',
                    $group,
                ),
            ),
            Controls::preRead('memberOf'),
            Controls::postRead('memberOf'),
        );
        $this->ldapClient()->delete($group);

        self::assertSame(
            [[$group], [$group], null],
            [
                $this->readEntryValues(
                    $add,
                    Control::OID_POST_READ,
                    'memberOf',
                ),
                $this->readEntryValues(
                    $modify,
                    Control::OID_PRE_READ,
                    'memberOf',
                ),
                $this->readEntryValues(
                    $modify,
                    Control::OID_POST_READ,
                    'memberOf',
                ),
            ],
        );
    }

    /**
     * @return iterable<string, array{list<Control>}>
     */
    public static function groupRemovals(): iterable
    {
        yield 'delete' => [[]];
        yield 'subtree delete' => [[Controls::subtreeDelete()]];
    }

    /**
     * @param list<Control> $controls
     */
    #[DataProvider('groupRemovals')]
    public function testThePreReadOfARemovedGroupCarriesItsMembers(array $controls): void
    {
        $this->authenticateAdmin();
        $group = 'cn=read-removed,dc=foo,dc=bar';
        $members = [
            'cn=user,dc=foo,dc=bar',
            'cn=admin,dc=foo,dc=bar',
        ];
        $this->ldapClient()->create(Entry::fromArray(
            $group,
            [
                'objectClass' => ['groupOfNames'],
                'cn' => ['read-removed'],
                'member' => $members,
            ],
        ));

        $response = $this->ldapClient()->sendAndReceive(
            Operations::delete($group),
            Controls::preRead('member'),
            ...$controls,
        );

        self::assertEqualsCanonicalizing(
            $members,
            $this->readEntryValues(
                $response,
                Control::OID_PRE_READ,
                'member',
            ),
        );
    }

    /**
     * @return list<string>|null
     */
    private function readEntryValues(
        LdapMessageResponse $response,
        string $oid,
        string $attribute,
    ): ?array {
        $control = $response->controls()->get($oid);

        $values = $control instanceof ReadEntryResponseControl
            ? $control->getEntry()->get($attribute)?->getValues()
            : null;

        return $values === null
            ? null
            : array_values($values);
    }
}
