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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

class LdapBackendStorageTest extends ServerTestCase
{
    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer('ldap-backend-storage', 'tcp');
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    protected function authenticateUser(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');
    }

    public function testBindWithCorrectCredentials(): void
    {
        // No exception thrown — bind succeeded; verify the session is usable
        $this->authenticateUser();

        self::assertTrue(
            $this->ldapClient()->compare('cn=user,dc=foo,dc=bar', 'cn', 'user')
        );
    }

    public function testBindWithWrongCredentials(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', 'wrongpassword');
    }

    public function testBindWithUnknownDn(): void
    {
        $this->expectException(BindException::class);

        $this->ldapClient()->bind('cn=nobody,dc=foo,dc=bar', '12345');
    }

    public function testSearchBaseObjectReturnsBaseEntry(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useBaseScope()
        );

        self::assertCount(1, $entries);
        self::assertSame('dc=foo,dc=bar', $entries->first()?->getDn()->toString());
    }

    public function testSearchSingleLevelReturnsDirectChildrenOnly(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useSingleLevelScope()
        );

        // cn=user and ou=people are direct children; cn=alice is not
        self::assertCount(2, $entries);
    }

    public function testSearchSubtreeWithFilterReturnsMatchingEntry(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=alice,ou=people,dc=foo,dc=bar',
            $entries->first()?->getDn()->toString()
        );
    }

    public function testSearchReturnsAttributeValues(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );

        $alice = $entries->first();
        self::assertNotNull($alice);
        self::assertSame(['Smith'], $alice->get('sn')?->getValues());
    }

    public function testSearchTypesOnlyReturnsAttributeNamesWithoutValues(): void
    {
        $this->authenticateUser();

        $request = Operations::search(Filters::equal('cn', 'alice'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();
        $request->setAttributesOnly(true);

        $entries = $this->ldapClient()->search($request);

        $alice = $entries->first();
        self::assertNotNull($alice);
        // sn attribute should be present but with no values
        $sn = $alice->get('sn');
        self::assertNotNull($sn);
        self::assertEmpty($sn->getValues());
    }

    public function testSearchWithNoMatchReturnsEmptyResult(): void
    {
        $this->authenticateUser();

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'nobody'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );

        self::assertCount(0, $entries);
    }

    public function testAddStoresEntry(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->ldapClient()->create(Entry::fromArray(
            'cn=charlie,dc=foo,dc=bar',
            ['cn' => 'charlie', 'objectClass' => 'inetOrgPerson']
        ));

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'charlie'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );
        self::assertCount(1, $entries);
    }

    public function testAddDuplicateDnFails(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=user,dc=foo,dc=bar',
            ['cn' => 'user']
        ));
    }

    public function testDeleteRemovesEntry(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');
        $this->ldapClient()->delete('cn=alice,ou=people,dc=foo,dc=bar');

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );
        self::assertCount(0, $entries);
    }

    public function testDeleteNonLeafEntryFails(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NOT_ALLOWED_ON_NON_LEAF);

        // ou=people still has cn=alice as a child
        $this->ldapClient()->delete('ou=people,dc=foo,dc=bar');
    }

    public function testModifyReplacesAttributeValue(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');

        $entry = Entry::fromArray('cn=alice,ou=people,dc=foo,dc=bar');
        $entry->set('sn', 'Jones');
        $this->ldapClient()->update($entry);

        $entries = $this->ldapClient()->search(
            Operations::search(Filters::equal('sn', 'Jones'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );
        self::assertCount(1, $entries);
        self::assertSame(['Jones'], $entries->first()?->get('sn')?->getValues());
    }

    public function testRenameChangesRdn(): void
    {
        $this->ldapClient()->bind('cn=user,dc=foo,dc=bar', '12345');
        $this->ldapClient()->rename('cn=alice,ou=people,dc=foo,dc=bar', 'cn=bob', true);

        $found = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'bob'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );
        self::assertCount(1, $found);
        self::assertSame('cn=bob,ou=people,dc=foo,dc=bar', $found->first()?->getDn()->toString());

        // Old DN should no longer exist
        $notFound = $this->ldapClient()->search(
            Operations::search(Filters::equal('cn', 'alice'))
                ->base('dc=foo,dc=bar')
                ->useSubtreeScope()
        );
        self::assertCount(0, $notFound);
    }

    public function testCompareReturnsTrueForMatchingValue(): void
    {
        $this->authenticateUser();

        $result = $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Smith'
        );

        self::assertTrue($result);
    }

    public function testCompareReturnsFalseForNonMatchingValue(): void
    {
        $this->authenticateUser();

        $result = $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Jones'
        );

        self::assertFalse($result);
    }

    public function testPagingReturnsAllEntriesAcrossMultiplePages(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $paging = $this->ldapClient()->paging($search, 2);

        $allEntries = [];

        while ($paging->hasEntries()) {
            foreach ($paging->getEntries() as $entry) {
                $allEntries[] = $entry->getDn()->toString();
            }
        }

        // Seed has 4 entries: dc=foo,dc=bar + cn=user + ou=people + cn=alice
        self::assertCount(4, $allEntries);
    }

    public function testPagingCanBeAbandoned(): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        $paging = $this->ldapClient()->paging($search, 1);

        // Get the first page only, then abandon
        $paging->getEntries();
        $paging->end();

        // After abandonment, hasEntries() must return false
        self::assertFalse($paging->hasEntries());
    }
}
