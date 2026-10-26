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

use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Add, delete, modify, and rename against the backend.
 */
trait WriteOperationTestsTrait
{
    public function testAddStoresEntry(): void
    {
        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            'cn=charlie,dc=foo,dc=bar',
            ['cn' => 'charlie', 'sn' => 'Charlie', 'objectClass' => 'inetOrgPerson'],
        )));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'charlie'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=charlie,dc=foo,dc=bar'));

        self::assertCount(
            1,
            $entries,
        );
    }

    public function testAddPreservesAttributeOptionsOnRoundTrip(): void
    {
        $this->asAdmin(fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            'cn=tagged,dc=foo,dc=bar',
            [
                'cn' => 'tagged',
                'cn;lang-en' => 'Tagged EN',
                'sn' => 'Tag',
                'objectClass' => 'inetOrgPerson',
            ],
        )));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn;lang-en', 'Tagged EN'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );

        $tagged = $entries->first();
        self::assertNotNull($tagged);
        self::assertSame(
            ['Tagged EN'],
            $tagged->get(new Attribute('cn;lang-en'), true)?->getValues(),
        );
        self::assertSame(
            ['tagged'],
            $tagged->get(new Attribute('cn'), true)?->getValues(),
        );
    }

    public function testModifyingABaseFormReindexesItWhenAnOptionBearingFormExists(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'cn=subtyped,dc=foo,dc=bar',
                [
                    'cn' => 'subtyped',
                    'sn' => 'Sub',
                    'mail' => 'base@foo.bar',
                    'mail;lang-en' => 'tagged@foo.bar',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));

            $entry = Entry::fromArray('cn=subtyped,dc=foo,dc=bar');
            $entry->changes()->add(Change::replace(new Attribute('mail', 'replaced@foo.bar')));
            $admin->update($entry);
        });

        self::assertCount(
            1,
            $this->mailSearch('replaced@foo.bar'),
            'The value the entry now holds must be found.',
        );
        self::assertCount(
            0,
            $this->mailSearch('base@foo.bar'),
            'The value the entry no longer holds must not be found.',
        );
        self::assertCount(
            1,
            $this->mailSearch('tagged@foo.bar'),
            'The untouched option-bearing form must still be found.',
        );
    }

    public function testAddRejectsAnAttributeCarryingNoValues(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->ldapClient()->create(new Entry(
            'cn=novalues,dc=foo,dc=bar',
            new Attribute('objectClass', 'inetOrgPerson'),
            new Attribute('cn', 'novalues'),
            new Attribute('sn', 'Novalues'),
            new Attribute('description'),
        ));
    }

    public function testModifyRejectsAnAddCarryingNoValues(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->ldapClient()->send(Operations::modify(
            'cn=alice,ou=people,dc=foo,dc=bar',
            Change::add(new Attribute('description')),
        ));
    }

    public function testNothingCanBeAddedOrMovedBeneathAnAlias(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->create(new Entry(
            'cn=ptr,dc=foo,dc=bar',
            new Attribute('objectClass', 'top', 'alias', 'extensibleObject'),
            new Attribute('cn', 'ptr'),
            new Attribute('aliasedObjectName', 'cn=user,dc=foo,dc=bar'),
        ));

        try {
            foreach ($this->placementsBeneath('cn=ptr,dc=foo,dc=bar') as $request) {
                try {
                    $this->ldapClient()->send($request);
                    self::fail('A placement beneath an alias should have been refused.');
                } catch (OperationException $e) {
                    self::assertSame(
                        ResultCode::ALIAS_PROBLEM,
                        $e->getCode(),
                    );
                }
            }

            $this->authenticateUser();

            self::assertNotNull($this->ldapClient()->read('cn=user,dc=foo,dc=bar'));
        } finally {
            $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=ptr,dc=foo,dc=bar'));
        }
    }

    public function testAddDuplicateDnFails(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=user,dc=foo,dc=bar',
            ['cn' => 'user', 'sn' => 'User', 'objectClass' => 'inetOrgPerson'],
        ));
    }

    public function testDeleteRemovesEntry(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'cn=delete-target,ou=people,dc=foo,dc=bar',
                ['cn' => 'delete-target', 'sn' => 'Target', 'objectClass' => 'inetOrgPerson'],
            ));

            $admin->delete('cn=delete-target,ou=people,dc=foo,dc=bar');
        });

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'delete-target'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(
            0,
            $entries,
        );
    }

    public function testDeleteNonLeafEntryFails(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NOT_ALLOWED_ON_NON_LEAF);

        // ou=people still has cn=alice as a child
        $this->ldapClient()->delete('ou=people,dc=foo,dc=bar');
    }

    public function testModifyReplacesAttributeValue(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'cn=modify-target,ou=people,dc=foo,dc=bar',
                ['cn' => 'modify-target', 'sn' => 'Smith', 'objectClass' => 'inetOrgPerson'],
            ));

            $entry = Entry::fromArray('cn=modify-target,ou=people,dc=foo,dc=bar');
            $entry->set('sn', 'Jones');
            $admin->update($entry);
        });

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'Jones'))
                ->base('cn=modify-target,ou=people,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=modify-target,ou=people,dc=foo,dc=bar'));

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            ['Jones'],
            $entries->first()?->get('sn')?->getValues(),
        );
    }

    public function testRejectedModifyLeavesTheEntryUnchanged(): void
    {
        $this->authenticateAdmin();

        // cn=user has no extensibleObject class, so removing a required attribute is actually refused.
        $entry = Entry::fromArray('cn=user,dc=foo,dc=bar');
        $entry->reset('sn');

        try {
            $this->ldapClient()->update($entry);
            self::fail('The schema violating modify should have been rejected.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::OBJECT_CLASS_VIOLATION,
                $e->getCode(),
            );
        }
        $this->authenticateUser();

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'sn')
                ->base('cn=user,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['Admin'],
            $found->first()?->get('sn')?->getValues(),
        );
    }

    public function testModifyDeletingEveryValueRemovesTheAttribute(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'cn=dropmail,dc=foo,dc=bar',
                [
                    'cn' => 'dropmail',
                    'sn' => 'Drop',
                    'mail' => ['one@foo.bar', 'two@foo.bar'],
                    'objectClass' => 'inetOrgPerson',
                ],
            ));

            $admin->send(Operations::modify(
                'cn=dropmail,dc=foo,dc=bar',
                Change::delete(new Attribute('mail', 'one@foo.bar', 'two@foo.bar')),
            ));
        });

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'mail')
                ->base('cn=dropmail,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertNull($found->first()?->get('mail'));

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=dropmail,dc=foo,dc=bar'));
    }

    public function testRenameDropsAnRdnAttributeLeftWithNoValues(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'employeeNumber=E1,dc=foo,dc=bar',
                [
                    'cn' => 'pruneme',
                    'sn' => 'Prune',
                    'employeeNumber' => 'E1',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));

            $admin->rename('employeeNumber=E1,dc=foo,dc=bar', 'cn=pruneme', true);
        });

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'employeeNumber')
                ->base('cn=pruneme,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertNull($found->first()?->get('employeeNumber'));

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=pruneme,dc=foo,dc=bar'));
    }

    public function testRenameKeepsAnRdnAttributeHoldingOtherValues(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'cn=keepme,dc=foo,dc=bar',
                ['cn' => ['keepme', 'kept'], 'sn' => 'Keep', 'objectClass' => 'inetOrgPerson'],
            ));

            $admin->rename('cn=keepme,dc=foo,dc=bar', 'cn=kept', true);
        });

        $found = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'), 'cn')
                ->base('cn=kept,dc=foo,dc=bar')
                ->useBaseScope(),
        );
        self::assertSame(
            ['kept'],
            $found->first()?->get('cn')?->getValues(),
        );

        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=kept,dc=foo,dc=bar'));
    }

    public function testRenameChangesRdn(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'cn=rename-target,ou=people,dc=foo,dc=bar',
                ['cn' => 'rename-target', 'sn' => 'Target', 'objectClass' => 'inetOrgPerson'],
            ));
            $admin->rename(
                'cn=rename-target,ou=people,dc=foo,dc=bar',
                'cn=renamed',
                true,
            );
        });

        $found = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'renamed'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        $notFound = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'rename-target'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        $this->asAdmin(fn(LdapClient $admin) => $admin->delete('cn=renamed,ou=people,dc=foo,dc=bar'));

        self::assertCount(
            1,
            $found,
        );
        self::assertSame(
            'cn=renamed,ou=people,dc=foo,dc=bar',
            $found->first()?->getDn()->toString(),
        );
        self::assertCount(
            0,
            $notFound,
        );
    }

    public function testARelaxedAddRefusesAnEntryUuidAnotherEntryHolds(): void
    {
        // The lookup runs inside the add's transaction, which on Swoole is the writer's connection.
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--allow-relax',
            ],
        );
        $this->authenticateAdmin();
        $uuid = '597ae2f6-16a6-1027-98f4-d28b5365dc14';

        $this->ldapClient()->send(
            Operations::add(new Entry(
                'cn=uuid-first,dc=foo,dc=bar',
                new Attribute('objectClass', 'top', 'person'),
                new Attribute('cn', 'uuid-first'),
                new Attribute('sn', 'First'),
                new Attribute('entryUUID', $uuid),
            )),
            Controls::relaxRules(),
        );

        try {
            $this->ldapClient()->send(
                Operations::add(new Entry(
                    'cn=uuid-second,dc=foo,dc=bar',
                    new Attribute('objectClass', 'top', 'person'),
                    new Attribute('cn', 'uuid-second'),
                    new Attribute('sn', 'Second'),
                    new Attribute('entryUUID', $uuid),
                )),
                Controls::relaxRules(),
            );
            self::fail('The second add reuses an entryUUID and should be refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }
        $this->authenticateUser();

        $first = $this->ldapClient()->read(
            'cn=uuid-first,dc=foo,dc=bar',
            ['entryUUID'],
        );

        self::assertSame(
            [$uuid, null],
            [
                $first?->get('entryUUID')?->firstValue(),
                $this->ldapClient()->read('cn=uuid-second,dc=foo,dc=bar'),
            ],
        );
    }

    /**
     * @return list<RequestInterface>
     */
    private function placementsBeneath(string $parentDn): array
    {
        return [
            Operations::add(new Entry(
                'cn=child,' . $parentDn,
                new Attribute('objectClass', 'top', 'person'),
                new Attribute('cn', 'child'),
                new Attribute('sn', 'Child'),
            )),
            Operations::move(
                'cn=user,dc=foo,dc=bar',
                $parentDn,
            ),
        ];
    }

    private function mailSearch(string $value): Entries
    {
        return $this->ldapClient()->search(
            Operations::search(Filters::equal('mail', $value))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
    }
}
