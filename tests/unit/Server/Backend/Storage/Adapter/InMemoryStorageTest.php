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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use PHPUnit\Framework\TestCase;

final class InMemoryStorageTest extends TestCase
{
    private InMemoryStorage $subject;

    private Entry $alice;

    protected function setUp(): void
    {
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );
        $this->subject = new InMemoryStorage([$this->alice]);
    }

    public function test_find_returns_entry_by_norm_dn(): void
    {
        $entry = $this->subject->find(new Dn('cn=alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $entry->getDn()->toString(),
        );
    }

    public function test_find_returns_null_for_unknown_norm_dn(): void
    {
        self::assertNull($this->subject->find(new Dn('cn=nobody,dc=example,dc=com')));
    }

    public function test_list_returns_all_entries(): void
    {
        $entries = iterator_to_array($this->subject->list(new Dn(''), true));

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $entries[0]->getDn()->toString(),
        );
    }

    public function test_list_single_level_returns_direct_children_only(): void
    {
        $parent = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $child = new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob'));
        $grandchild = new Entry(new Dn('cn=Sub,cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $storage = new InMemoryStorage([$parent, $child, $grandchild]);

        $entries = iterator_to_array($storage->list(new Dn('dc=example,dc=com'), false));

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            'cn=Bob,dc=example,dc=com',
            $entries[0]->getDn()->toString(),
        );
    }

    public function test_list_recursive_includes_base_and_descendants(): void
    {
        $parent = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $child = new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob'));
        $grandchild = new Entry(new Dn('cn=Sub,cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $storage = new InMemoryStorage([$parent, $child, $grandchild]);

        $entries = iterator_to_array($storage->list(new Dn('dc=example,dc=com'), true));

        self::assertCount(
            3,
            $entries,
        );
    }

    public function test_has_children_returns_true_when_children_exist(): void
    {
        $parent = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $child = new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice'));
        $storage = new InMemoryStorage([$parent, $child]);

        self::assertTrue($storage->hasChildren(new Dn('dc=example,dc=com')));
    }

    public function test_has_children_returns_false_for_leaf_entry(): void
    {
        self::assertFalse($this->subject->hasChildren(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_store_adds_entry(): void
    {
        $bob = new Entry(new Dn('cn=Bob,dc=example,dc=com'), new Attribute('cn', 'Bob'));
        $this->subject->store($bob);

        self::assertNotNull($this->subject->find(new Dn('cn=bob,dc=example,dc=com')));
    }

    public function test_store_replaces_existing_entry(): void
    {
        $updated = new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alicia'));
        $this->subject->store($updated);

        $entry = $this->subject->find(new Dn('cn=alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertSame(
            ['Alicia'],
            $entry->get('cn')?->getValues(),
        );
    }

    public function test_remove_deletes_entry(): void
    {
        $this->subject->remove(new Dn('cn=alice,dc=example,dc=com'));

        self::assertNull($this->subject->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_remove_is_noop_for_unknown_norm_dn(): void
    {
        $this->subject->remove(new Dn('cn=nobody,dc=example,dc=com'));

        self::assertCount(
            1,
            iterator_to_array($this->subject->list(new Dn(''), true)),
        );
    }

    public function test_constructor_normalises_dn_keys(): void
    {
        $entry = new Entry(new Dn('CN=ALICE,DC=EXAMPLE,DC=COM'), new Attribute('cn', 'Alice'));
        $storage = new InMemoryStorage([$entry]);

        self::assertNotNull($storage->find(new Dn('cn=alice,dc=example,dc=com')));
    }

    public function test_empty_constructor_creates_empty_storage(): void
    {
        $storage = new InMemoryStorage();

        self::assertCount(
            0,
            iterator_to_array($storage->list(new Dn(''), true)),
        );
    }
}
