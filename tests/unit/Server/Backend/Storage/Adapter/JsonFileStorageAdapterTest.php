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
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorageAdapter;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use PHPUnit\Framework\TestCase;

final class JsonFileStorageAdapterTest extends TestCase
{
    private JsonFileStorageAdapter $subject;

    private string $tempFile;

    private Entry $base;

    private Entry $alice;

    private Entry $bob;

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/ldap_test_' . uniqid() . '.json';

        $this->base = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
            new Attribute('objectClass', 'dcObject'),
        );
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('userPassword', 'secret'),
        );
        $this->bob = new Entry(
            new Dn('cn=Bob,ou=People,dc=example,dc=com'),
            new Attribute('cn', 'Bob'),
        );

        $this->subject = JsonFileStorageAdapter::forPcntl($this->tempFile);
        $this->subject->add(new AddCommand($this->base));
        $this->subject->add(new AddCommand($this->alice));
        $this->subject->add(new AddCommand($this->bob));
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
        self::assertSame('cn=Alice,dc=example,dc=com', $entry->getDn()->toString());
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
        $adapter = JsonFileStorageAdapter::forPcntl($this->tempFile . '.nonexistent');

        self::assertNull($adapter->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_search_base_scope_returns_only_base(): void
    {
        $entries = iterator_to_array($this->subject->search(new SearchContext(
            baseDn: new Dn('dc=example,dc=com'),
            scope: SearchRequest::SCOPE_BASE_OBJECT,
            filter: new PresentFilter('objectClass'),
            attributes: [],
            typesOnly: false,
        )));

        self::assertCount(1, $entries);
        self::assertSame(
            'dc=example,dc=com',
            array_values($entries)[0]->getDn()->toString()
        );
    }

    public function test_search_single_level_returns_direct_children(): void
    {
        $entries = iterator_to_array($this->subject->search(new SearchContext(
            baseDn: new Dn('dc=example,dc=com'),
            scope: SearchRequest::SCOPE_SINGLE_LEVEL,
            filter: new PresentFilter('objectClass'),
            attributes: [],
            typesOnly: false,
        )));

        // Only alice is a direct child of dc=example,dc=com; bob is under ou=People
        self::assertCount(1, $entries);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            array_values($entries)[0]->getDn()->toString()
        );
    }

    public function test_search_subtree_returns_base_and_all_descendants(): void
    {
        $entries = iterator_to_array($this->subject->search(new SearchContext(
            baseDn: new Dn('dc=example,dc=com'),
            scope: SearchRequest::SCOPE_WHOLE_SUBTREE,
            filter: new PresentFilter('objectClass'),
            attributes: [],
            typesOnly: false,
        )));

        self::assertCount(
            3,
            $entries
        );
    }

    public function test_add_stores_entry(): void
    {
        $entry = new Entry(new Dn('cn=New,dc=example,dc=com'), new Attribute('cn', 'New'));
        $this->subject->add(new AddCommand($entry));

        self::assertNotNull($this->subject->get(new Dn('cn=New,dc=example,dc=com')));
    }

    public function test_add_persists_to_file(): void
    {
        $entry = new Entry(new Dn('cn=Persistent,dc=example,dc=com'), new Attribute('cn', 'Persistent'));
        $this->subject->add(new AddCommand($entry));

        // A second independent adapter instance reading the same file should see the new entry
        $adapter2 = JsonFileStorageAdapter::forPcntl($this->tempFile);

        self::assertNotNull($adapter2->get(new Dn('cn=Persistent,dc=example,dc=com')));
    }

    public function test_delete_removes_entry(): void
    {
        $this->subject->delete(new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')));

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_delete_persists_to_file(): void
    {
        $this->subject->delete(new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')));

        $adapter2 = JsonFileStorageAdapter::forPcntl($this->tempFile);

        self::assertNull($adapter2->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_delete_throws_not_allowed_on_non_leaf_when_entry_has_subordinates(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NOT_ALLOWED_ON_NON_LEAF);

        // dc=example,dc=com has cn=Alice as a direct child — cannot be deleted
        $this->subject->delete(new DeleteCommand(new Dn('dc=example,dc=com')));
    }

    public function test_update_add_attribute_value(): void
    {
        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_ADD, 'mail', 'alice@example.com')],
        ));

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertNotNull($entry);
        self::assertTrue($entry->get('mail')?->has('alice@example.com'));
    }

    public function test_update_replace_attribute_value(): void
    {
        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'cn', 'Alicia')],
        ));

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertSame(['Alicia'], $entry?->get('cn')?->getValues());
    }

    public function test_update_delete_attribute(): void
    {
        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'userPassword')],
        ));

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertNull($entry?->get('userPassword'));
    }

    public function test_update_delete_specific_attribute_value(): void
    {
        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_ADD, 'mail', 'a@b.com', 'c@d.com')],
        ));
        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_DELETE, 'mail', 'a@b.com')],
        ));

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));
        $mail = $entry?->get('mail');

        self::assertNotNull($mail);
        self::assertFalse($mail->has('a@b.com'));
        self::assertTrue($mail->has('c@d.com'));
    }

    public function test_move_renames_entry(): void
    {
        $this->subject->move(new MoveCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('cn=Alicia'),
            true,
            null,
        ));

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
        self::assertNotNull($this->subject->get(new Dn('cn=Alicia,dc=example,dc=com')));
    }

    public function test_update_throws_no_such_object_for_missing_entry(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->update(new UpdateCommand(
            new Dn('cn=Nobody,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'cn', 'Nobody')],
        ));
    }

    public function test_add_throws_entry_already_exists(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->subject->add(new AddCommand($this->alice));
    }

    public function test_update_add_value_to_existing_attribute(): void
    {
        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_ADD, 'cn', 'Alicia')],
        ));

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertNotNull($entry);

        $cn = $entry->get('cn');
        self::assertNotNull($cn);

        self::assertTrue($cn->has('Alice'));
        self::assertTrue($cn->has('Alicia'));
    }

    public function test_update_replace_with_no_values_clears_attribute(): void
    {
        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'userPassword')],
        ));

        self::assertNull(
            $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'))?->get('userPassword')
        );
    }

    public function test_move_throws_no_such_object_for_missing_entry(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->move(new MoveCommand(
            new Dn('cn=Nobody,dc=example,dc=com'),
            Rdn::create('cn=Ghost'),
            true,
            null,
        ));
    }

    public function test_move_creates_new_rdn_attribute_when_it_does_not_exist_in_entry(): void
    {
        // Alice has no 'uid' attribute; renaming to uid=alice should create it.
        $this->subject->move(new MoveCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('uid=alice'),
            false,
            null,
        ));

        $entry = $this->subject->get(new Dn('uid=alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertTrue($entry->get('uid')?->has('alice'));
    }

    public function test_move_to_new_parent(): void
    {
        $ou = new Entry(new Dn('ou=People,dc=example,dc=com'), new Attribute('ou', 'People'));
        $this->subject->add(new AddCommand($ou));

        $this->subject->move(new MoveCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('cn=Alice'),
            false,
            new Dn('ou=People,dc=example,dc=com'),
        ));

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
        self::assertNotNull($this->subject->get(new Dn('cn=Alice,ou=People,dc=example,dc=com')));
    }

    public function test_get_on_empty_file_returns_null(): void
    {
        file_put_contents($this->tempFile, '');

        $adapter = JsonFileStorageAdapter::forPcntl($this->tempFile);

        self::assertNull($adapter->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_get_on_invalid_json_returns_null(): void
    {
        file_put_contents($this->tempFile, 'not valid json {{{');

        $adapter = JsonFileStorageAdapter::forPcntl($this->tempFile);

        self::assertNull($adapter->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_get_uses_in_memory_cache_on_subsequent_calls(): void
    {
        // First call populates the cache.
        $first = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        // Corrupt the file — a cache-bypassing read would return null.
        file_put_contents($this->tempFile, 'corrupted');

        $adapter = JsonFileStorageAdapter::forPcntl($this->tempFile);

        // Prime the cache on first call (returns null from corrupted file).
        $adapter->get(new Dn('cn=Alice,dc=example,dc=com'));

        // Second call on same adapter+same mtime must use the in-memory cache.
        $result = $adapter->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNull($result);
        self::assertNotNull($first);
    }

    public function test_get_cache_is_invalidated_when_file_mtime_changes(): void
    {
        $adapter = JsonFileStorageAdapter::forPcntl($this->tempFile);

        // Prime the cache with a valid file (contains Alice).
        self::assertNotNull($adapter->get(new Dn('cn=Alice,dc=example,dc=com')));

        // A write operation (add) changes the file — cache is cleared.
        $extra = new Entry(new Dn('cn=Extra,dc=example,dc=com'), new Attribute('cn', 'Extra'));
        $adapter->add(new AddCommand($extra));

        // The adapter must re-read the file and see the new entry.
        self::assertNotNull($adapter->get(new Dn('cn=Extra,dc=example,dc=com')));
    }

    public function test_supports_returns_true_for_all_write_commands(): void
    {
        self::assertTrue($this->subject->supports(new AddCommand($this->alice)));
        self::assertTrue($this->subject->supports(new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com'))));
        self::assertTrue($this->subject->supports(new UpdateCommand(new Dn('cn=Alice,dc=example,dc=com'), [])));
        self::assertTrue($this->subject->supports(new MoveCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('cn=Alice'),
            false,
            null,
        )));
    }

    public function test_supports_returns_false_for_unknown_request(): void
    {
        $unknown = $this->createMock(WriteRequestInterface::class);

        self::assertFalse($this->subject->supports($unknown));
    }

    public function test_handle_dispatches_to_correct_method(): void
    {
        $entry = new Entry(new Dn('cn=New,dc=example,dc=com'), new Attribute('cn', 'New'));
        $this->subject->handle(new AddCommand($entry));

        self::assertNotNull($this->subject->get(new Dn('cn=New,dc=example,dc=com')));
    }
}
