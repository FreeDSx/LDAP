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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

trait EntryReadTestsTrait
{
    /**
     * Linked values come back as the target's current name, which may differ in spelling from the value written.
     */
    private const READ_LINKED_TYPES = [
        'memberOf',
        'seeAlso',
    ];

    private const READ_GENERATED_SYNTAX = [
        'createTimestamp' => '/^\d{14}Z$/',
        'entryUUID' => '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/',
        'modifyTimestamp' => '/^\d{14}Z$/',
        'pwdChangedTime' => '/^\d{14}Z$/',
    ];

    private const READ_GENERATED_VALUE = 'a generated value';

    #[DataProvider('entryReadPathProvider')]
    public function testReadingAnEntryReturnsEveryUserAttributeItHolds(int $scope): void
    {
        $name = 'read-user-' . $scope;
        $this->seedReadEntry($name);
        $entry = $this->readEntryVia(
            $scope,
            $name,
            '*',
        );

        self::assertSame(
            $this->comparableAttributes($this->expectedUserAttributes($name)),
            $this->comparableAttributes($entry->toArray()),
        );
    }

    #[DataProvider('entryReadPathProvider')]
    public function testReadingAnEntryReturnsEveryOperationalAttribute(int $scope): void
    {
        $name = 'read-operational-' . $scope;
        [$dn, $group] = $this->seedReadEntry($name);
        $entry = $this->readEntryVia(
            $scope,
            $name,
            '+',
        );

        self::assertSame(
            $this->comparableAttributes($this->expectedOperationalAttributes(
                $dn,
                $group,
            )),
            $this->comparableAttributes($entry->toArray()),
        );
    }

    #[DataProvider('entryReadPathProvider')]
    public function testReadingAnEntryWithBothWildcardsReturnsEveryAttribute(int $scope): void
    {
        $name = 'read-both-' . $scope;
        [$dn, $group] = $this->seedReadEntry($name);
        $entry = $this->readEntryVia(
            $scope,
            $name,
            '*',
            '+',
        );

        self::assertSame(
            $this->comparableAttributes([
                ...$this->expectedUserAttributes($name),
                ...$this->expectedOperationalAttributes(
                    $dn,
                    $group,
                ),
            ]),
            $this->comparableAttributes($entry->toArray()),
        );
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function entryReadPathProvider(): iterable
    {
        yield 'a base-scope read' => [SearchRequest::SCOPE_BASE_OBJECT];
        yield 'a subtree search' => [SearchRequest::SCOPE_WHOLE_SUBTREE];
    }

    /**
     * A person holding every kind of value a read returns or withholds, and a group naming it.
     *
     * @return array{string, string} The person's DN and the group's.
     */
    private function seedReadEntry(string $name): array
    {
        $area = $this->readAreaDn($name);
        $dn = $this->readEntryDn($name);
        $group = "cn={$name}-group,dc=foo,dc=bar";

        $this->asAdmin(function (LdapClient $admin) use ($name, $area, $dn, $group): void {
            $admin->create(Entry::fromArray(
                $area,
                [
                    'objectClass' => 'organizationalUnit',
                    'ou' => $name,
                    'administrativeRole' => '2.5.23.4',
                ],
            ));
            $admin->create(Entry::fromArray(
                "cn=password-policy,{$area}",
                [
                    'objectClass' => ['subentry', 'pwdPolicy'],
                    'cn' => 'password-policy',
                    'subtreeSpecification' => '{}',
                    'pwdAttribute' => 'userPassword',
                    'pwdInHistory' => '1',
                ],
            ));
            $admin->create(Entry::fromArray(
                $dn,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => [$name, 'Entry Reader'],
                    'sn' => 'Reader',
                    'displayName' => 'Straße',
                    'employeeNumber' => 'A1b2C3',
                    'mail' => ['reader@foo.bar', 'reader-two@foo.bar'],
                    'mail;lang-en' => 'reader-en@foo.bar',
                    'telephoneNumber' => '+1 408 555 1212',
                    'seeAlso' => 'CN=Smith\, John, DC=Foo, DC=Bar',
                    'userPassword' => 'secret',
                ],
            ));
            // The policy moves the replaced password into pwdHistory.
            $admin->send(Operations::modify(
                $dn,
                Change::replace(
                    'userPassword',
                    'secret-changed',
                ),
            ));
            $admin->create(Entry::fromArray(
                $group,
                [
                    'objectClass' => 'groupOfNames',
                    'cn' => "{$name}-group",
                    'member' => $dn,
                ],
            ));
        });

        return [$dn, $group];
    }

    /**
     * @return array<string, list<string>>
     */
    private function expectedUserAttributes(string $name): array
    {
        return [
            'objectClass' => ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
            'cn' => [$name, 'Entry Reader'],
            'sn' => ['Reader'],
            'displayName' => ['Straße'],
            'employeeNumber' => ['A1b2C3'],
            'mail' => ['reader@foo.bar', 'reader-two@foo.bar'],
            'mail;lang-en' => ['reader-en@foo.bar'],
            'telephoneNumber' => ['+1 408 555 1212'],
            'seeAlso' => ['cn=Smith\, John,dc=foo,dc=bar'],
        ];
    }

    /**
     * @return array<string, list<string>>
     */
    private function expectedOperationalAttributes(
        string $dn,
        string $group,
    ): array {
        return [
            'createTimestamp' => [self::READ_GENERATED_VALUE],
            'creatorsName' => ['cn=admin,dc=foo,dc=bar'],
            'entryDN' => [$dn],
            'entryUUID' => [self::READ_GENERATED_VALUE],
            'hasSubordinates' => ['FALSE'],
            'memberOf' => [$group],
            'modifiersName' => ['cn=admin,dc=foo,dc=bar'],
            'modifyTimestamp' => [self::READ_GENERATED_VALUE],
            'pwdChangedTime' => [self::READ_GENERATED_VALUE],
            'structuralObjectClass' => ['inetOrgPerson'],
            'subschemaSubentry' => ['cn=Subschema'],
        ];
    }

    private function readEntryVia(
        int $scope,
        string $name,
        string ...$attributes,
    ): Entry {
        $request = $scope === SearchRequest::SCOPE_BASE_OBJECT
            ? Operations::read(
                $this->readEntryDn($name),
                ...$attributes,
            )
            : Operations::search(
                Filters::equal(
                    'cn',
                    $name,
                ),
                ...$attributes,
            )->base('dc=foo,dc=bar')->useSubtreeScope();
        $entries = $this->ldapClient()->search($request);

        self::assertCount(
            1,
            $entries,
        );

        return $entries->first() ?? self::fail('The read returned no entry.');
    }

    private function readAreaDn(string $name): string
    {
        return "ou={$name},ou=people,dc=foo,dc=bar";
    }

    private function readEntryDn(string $name): string
    {
        return "cn={$name},{$this->readAreaDn($name)}";
    }

    /**
     * The attributes in a fixed order, a linked value compared by name and a generated value by its syntax.
     *
     * @param array<string, array<string>> $attributes
     *
     * @return array<string, list<string>>
     */
    private function comparableAttributes(array $attributes): array
    {
        $comparable = [];

        foreach ($attributes as $name => $values) {
            $comparableValues = array_map(
                fn(string $value): string => $this->comparableValue(
                    $name,
                    $value,
                ),
                $values,
            );
            sort($comparableValues);
            $comparable[$name] = $comparableValues;
        }
        ksort($comparable);

        return $comparable;
    }

    private function comparableValue(
        string $name,
        string $value,
    ): string {
        if (in_array($name, self::READ_LINKED_TYPES, true)) {
            return Dn::normalized($value);
        }
        $syntax = self::READ_GENERATED_SYNTAX[$name] ?? null;

        return $syntax !== null && preg_match($syntax, $value) === 1
            ? self::READ_GENERATED_VALUE
            : $value;
    }
}
