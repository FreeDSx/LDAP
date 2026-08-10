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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Add, delete, modify, and rename against the backend.
 */
trait WriteTestsTrait
{
    public function testAddStoresEntry(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=charlie,dc=foo,dc=bar',
            ['cn' => 'charlie', 'sn' => 'Charlie', 'objectClass' => 'inetOrgPerson'],
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'charlie'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(1, $entries);
    }

    public function testAddPreservesAttributeOptionsOnRoundTrip(): void
    {
        $this->authenticateAdmin();

        $this->ldapClient()->create(Entry::fromArray(
            'cn=tagged,dc=foo,dc=bar',
            [
                'cn' => 'tagged',
                'cn;lang-en' => 'Tagged EN',
                'sn' => 'Tag',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

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
        $this->authenticateAdmin();
        $this->ldapClient()->delete('cn=alice,ou=people,dc=foo,dc=bar');

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(0, $entries);
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
        $this->authenticateAdmin();

        $entry = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $entry->set('sn', 'Jones');
        $this->ldapClient()->update($entry);

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'Jones'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(1, $entries);
        self::assertSame(['Jones'], $entries->first()?->get('sn')?->getValues());
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

    public function testRenameChangesRdn(): void
    {
        $this->authenticateAdmin();
        $this->ldapClient()->rename('cn=alice,ou=people,dc=foo,dc=bar', 'cn=bob', true);

        $found = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'bob'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(1, $found);
        self::assertSame('cn=bob,ou=people,dc=foo,dc=bar', $found->first()?->getDn()->toString());

        // Old DN should no longer exist
        $notFound = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope(),
        );
        self::assertCount(0, $notFound);
    }
}
