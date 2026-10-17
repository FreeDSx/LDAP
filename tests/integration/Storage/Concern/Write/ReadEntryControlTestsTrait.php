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
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operations;
use PHPUnit\Framework\Attributes\DataProvider;

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
        self::assertNull($this->ldapClient()->read('cn=child,ou=pre-read-tree,dc=foo,dc=bar'));
    }
}
