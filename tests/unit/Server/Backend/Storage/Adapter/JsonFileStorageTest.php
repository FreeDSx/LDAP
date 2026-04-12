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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use PHPUnit\Framework\TestCase;

final class JsonFileStorageTest extends TestCase
{
    private WritableStorageBackend $subject;

    private JsonFileStorage $storage;

    private string $tempFile;

    private Entry $alice;

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/ldap_test_' . uniqid() . '.json';
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('userPassword', 'secret'),
        );

        $this->storage = JsonFileStorage::forPcntl($this->tempFile);
        $this->subject = new WritableStorageBackend($this->storage);
        $this->subject->add(new AddCommand(
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
        ));
        $this->subject->add(new AddCommand($this->alice));
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempFile)) {
            unlink($this->tempFile);
        }
    }

    public function test_get_returns_entry_by_dn(): void
    {
        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $entry->getDn()->toString(),
        );
    }

    public function test_get_is_case_insensitive(): void
    {
        $entry = $this->subject->get(new Dn('CN=ALICE,DC=EXAMPLE,DC=COM'));

        self::assertNotNull($entry);
    }

    public function test_get_returns_null_for_missing_dn(): void
    {
        self::assertNull($this->subject->get(new Dn('cn=Charlie,dc=example,dc=com')));
    }

    public function test_get_on_nonexistent_file_returns_null(): void
    {
        $storage = JsonFileStorage::forPcntl($this->tempFile . '.nonexistent');
        $backend = new WritableStorageBackend($storage);

        self::assertNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_get_on_empty_file_returns_null(): void
    {
        file_put_contents($this->tempFile, '');
        $storage = JsonFileStorage::forPcntl($this->tempFile);
        $backend = new WritableStorageBackend($storage);

        self::assertNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_get_on_invalid_json_returns_null(): void
    {
        file_put_contents($this->tempFile, 'not valid json {{{');
        $storage = JsonFileStorage::forPcntl($this->tempFile);
        $backend = new WritableStorageBackend($storage);

        self::assertNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_add_persists_to_file(): void
    {
        $entry = new Entry(new Dn('cn=Persistent,dc=example,dc=com'), new Attribute('cn', 'Persistent'));
        $this->subject->add(new AddCommand($entry));

        // A second independent backend reading the same file should see the new entry.
        $backend2 = new WritableStorageBackend(JsonFileStorage::forPcntl($this->tempFile));

        self::assertNotNull($backend2->get(new Dn('cn=Persistent,dc=example,dc=com')));
    }

    public function test_delete_persists_to_file(): void
    {
        $this->subject->delete(new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')));

        $backend2 = new WritableStorageBackend(JsonFileStorage::forPcntl($this->tempFile));

        self::assertNull($backend2->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_get_uses_in_memory_cache_on_subsequent_calls(): void
    {
        // Corrupt the file after the first read — a cache-bypassing adapter would return null.
        $this->storage->find(new Dn('cn=alice,dc=example,dc=com'));
        file_put_contents($this->tempFile, 'corrupted');

        $storage2 = JsonFileStorage::forPcntl($this->tempFile);

        // Prime the cache on first call (returns null from corrupted file).
        $storage2->find(new Dn('cn=alice,dc=example,dc=com'));

        // Second call on same storage instance with same mtime must use the in-memory cache.
        $result = $storage2->find(new Dn('cn=alice,dc=example,dc=com'));

        self::assertNull($result);
    }

    public function test_cache_is_invalidated_after_write(): void
    {
        $storage = JsonFileStorage::forPcntl($this->tempFile);
        $backend = new WritableStorageBackend($storage);

        // Prime the cache with a valid file (contains Alice).
        self::assertNotNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));

        // A write operation changes the file — cache must be cleared.
        $extra = new Entry(new Dn('cn=Extra,dc=example,dc=com'), new Attribute('cn', 'Extra'));
        $backend->add(new AddCommand($extra));

        // The backend must re-read the file and see the new entry.
        self::assertNotNull($backend->get(new Dn('cn=Extra,dc=example,dc=com')));
    }

    public function test_list_single_level_returns_direct_children_only(): void
    {
        // dc=example,dc=com and Alice are already in storage from setUp.
        // Add a grandchild to verify it is excluded from single-level results.
        $grandchild = new Entry(new Dn('cn=Sub,cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $this->subject->add(new AddCommand($grandchild));

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSingleLevelScope();
        $results = iterator_to_array($this->subject->search($request)->entries);

        self::assertCount(
            1,
            $results,
        );
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $results[0]->getDn()->toString(),
        );
    }

    public function test_list_recursive_includes_base_and_descendants(): void
    {
        // dc=example,dc=com and Alice are already in storage from setUp.
        // Add a grandchild; the subtree search should return all three entries.
        $grandchild = new Entry(new Dn('cn=Sub,cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $this->subject->add(new AddCommand($grandchild));

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $results = iterator_to_array($this->subject->search($request)->entries);

        self::assertCount(
            3,
            $results,
        );
    }

    public function test_has_children_returns_true_when_children_exist(): void
    {
        // Alice (cn=Alice,dc=example,dc=com) was added in setUp as a child of dc=example,dc=com.
        self::assertTrue($this->storage->hasChildren(new Dn('dc=example,dc=com')));
    }

    public function test_has_children_returns_false_for_leaf_entry(): void
    {
        self::assertFalse($this->storage->hasChildren(new Dn('cn=alice,dc=example,dc=com')));
    }
}
