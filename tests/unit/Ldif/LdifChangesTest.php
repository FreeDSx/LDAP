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

namespace Tests\Unit\FreeDSx\Ldap\Ldif;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Ldif\LdifChangeRecord;
use FreeDSx\Ldap\Ldif\LdifChanges;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operations;
use PHPUnit\Framework\TestCase;

final class LdifChangesTest extends TestCase
{
    public function test_it_counts_and_iterates_in_construction_order(): void
    {
        $add = Operations::add(Entry::create('cn=a,dc=x', ['cn' => 'a']));
        $del = Operations::delete('cn=b,dc=x');

        $changes = new LdifChanges(
            new LdifChangeRecord($add),
            new LdifChangeRecord($del),
        );

        self::assertCount(
            2,
            $changes,
        );
        self::assertSame(
            [$add, $del],
            $changes->requests(),
        );
        self::assertSame(
            [$add, $del],
            array_map(
                static fn(LdifChangeRecord $record): RequestInterface => $record->request,
                iterator_to_array($changes->getIterator()),
            ),
        );
    }

    public function test_type_filters_split_by_request_class(): void
    {
        $add = Operations::add(Entry::create('cn=a,dc=x', ['cn' => 'a']));
        $modify = Operations::modify(
            'cn=a,dc=x',
            Change::replace('sn', 'Z'),
        );
        $delete = Operations::delete('cn=b,dc=x');
        $modDn = new ModifyDnRequest(
            'cn=c,dc=x',
            'cn=cc',
            true,
        );

        $changes = new LdifChanges(
            new LdifChangeRecord($add),
            new LdifChangeRecord($modify),
            new LdifChangeRecord($delete),
            new LdifChangeRecord($modDn),
        );

        self::assertSame(
            [$add],
            $changes->adds(),
        );
        self::assertSame(
            [$modify],
            $changes->modifies(),
        );
        self::assertSame(
            [$delete],
            $changes->deletes(),
        );
        self::assertSame(
            [$modDn],
            $changes->modifyDns(),
        );
    }

    public function test_isAddOnly_is_true_when_every_request_is_an_add(): void
    {
        $changes = new LdifChanges(
            new LdifChangeRecord(Operations::add(Entry::create('cn=a,dc=x', ['cn' => 'a']))),
            new LdifChangeRecord(Operations::add(Entry::create('cn=b,dc=x', ['cn' => 'b']))),
        );

        self::assertTrue($changes->isAddOnly());
    }

    public function test_isAddOnly_is_false_when_any_request_is_not_an_add(): void
    {
        $changes = new LdifChanges(
            new LdifChangeRecord(Operations::add(Entry::create('cn=a,dc=x', ['cn' => 'a']))),
            new LdifChangeRecord(Operations::delete('cn=b,dc=x')),
        );

        self::assertFalse($changes->isAddOnly());
    }

    public function test_isAddOnly_is_true_for_an_empty_collection(): void
    {
        self::assertTrue((new LdifChanges())->isAddOnly());
    }

    public function test_entries_extracts_entry_from_every_add_request_ignoring_others(): void
    {
        $foo = Entry::create('cn=foo,dc=x', ['cn' => 'foo']);
        $bar = Entry::create('cn=bar,dc=x', ['cn' => 'bar']);

        $changes = new LdifChanges(
            new LdifChangeRecord(Operations::add($foo)),
            new LdifChangeRecord(Operations::delete('cn=zap,dc=x')),
            new LdifChangeRecord(Operations::add($bar)),
        );

        self::assertSame(
            [$foo, $bar],
            $changes->entries(),
        );
    }
}
