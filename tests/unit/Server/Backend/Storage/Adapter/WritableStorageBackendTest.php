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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use PHPUnit\Framework\TestCase;

final class WritableStorageBackendTest extends TestCase
{
    private WritableStorageBackend $subject;

    private Entry $alice;

    private Entry $bob;

    private Entry $base;

    protected function setUp(): void
    {
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

        $this->subject = new WritableStorageBackend(new InMemoryStorage([
            $this->base,
            $this->alice,
            $this->bob,
        ]));
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

    public function test_search_base_scope_returns_only_base(): void
    {
        $entries = iterator_to_array($this->subject->search(new SearchContext(
            baseDn: new Dn('dc=example,dc=com'),
            scope: SearchRequest::SCOPE_BASE_OBJECT,
            filter: new PresentFilter('objectClass'),
            attributes: [],
            typesOnly: false,
        )));

        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            'dc=example,dc=com',
            array_values($entries)[0]->getDn()->toString(),
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
        self::assertCount(
            1,
            $entries,
        );
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            array_values($entries)[0]->getDn()->toString(),
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
            $entries,
        );
    }

    public function test_add_stores_entry(): void
    {
        $entry = new Entry(new Dn('cn=New,dc=example,dc=com'), new Attribute('cn', 'New'));
        $this->subject->add(new AddCommand($entry));

        self::assertNotNull($this->subject->get(new Dn('cn=New,dc=example,dc=com')));
    }

    public function test_add_throws_entry_already_exists(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->subject->add(new AddCommand($this->alice));
    }

    public function test_add_throws_no_such_object_when_parent_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $entry = new Entry(new Dn('cn=New,ou=Missing,dc=example,dc=com'), new Attribute('cn', 'New'));
        $this->subject->add(new AddCommand($entry));
    }

    public function test_add_allows_root_naming_context_entry(): void
    {
        $backend = new WritableStorageBackend(new InMemoryStorage());
        $root = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $backend->add(new AddCommand($root));

        self::assertNotNull($backend->get(new Dn('dc=example,dc=com')));
    }

    public function test_delete_removes_entry(): void
    {
        $this->subject->delete(new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')));

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_delete_throws_no_such_object_for_missing_entry(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->delete(new DeleteCommand(new Dn('cn=Nobody,dc=example,dc=com')));
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

    public function test_update_replace_attribute_value(): void
    {
        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'userPassword', 'newpassword')],
        ));

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertSame(
            ['newpassword'],
            $entry->get('userPassword')?->getValues(),
        );
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
            [new Change(Change::TYPE_DELETE, 'userPassword', 'secret')],
        ));

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertFalse($entry?->get('userPassword')?->has('secret') ?? false);
    }

    public function test_update_replace_with_no_values_clears_attribute(): void
    {
        $this->subject->update(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'userPassword')],
        ));

        self::assertNull(
            $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'))?->get('userPassword'),
        );
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

    public function test_move_throws_not_allowed_on_non_leaf_when_entry_has_children(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NOT_ALLOWED_ON_NON_LEAF);

        // dc=example,dc=com has cn=Alice as a direct child — cannot be moved
        $this->subject->move(new MoveCommand(
            new Dn('dc=example,dc=com'),
            Rdn::create('dc=example'),
            false,
            null,
        ));
    }

    public function test_move_throws_no_such_object_when_new_superior_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->move(new MoveCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('cn=Alice'),
            false,
            new Dn('ou=Missing,dc=example,dc=com'),
        ));
    }

    public function test_move_throws_entry_already_exists_when_target_dn_exists(): void
    {
        $alicia = new Entry(new Dn('cn=Alicia,dc=example,dc=com'), new Attribute('cn', 'Alicia'));
        $backend = new WritableStorageBackend(new InMemoryStorage([
            $this->base,
            $this->alice,
            $alicia,
        ]));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $backend->move(new MoveCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('cn=Alicia'),
            true,
            null,
        ));
    }

    public function test_supports_returns_true_for_add_command(): void
    {
        self::assertTrue($this->subject->supports(new AddCommand($this->alice)));
    }

    public function test_supports_returns_true_for_delete_command(): void
    {
        self::assertTrue($this->subject->supports(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
        ));
    }

    public function test_supports_returns_true_for_update_command(): void
    {
        self::assertTrue($this->subject->supports(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [],
        )));
    }

    public function test_supports_returns_true_for_move_command(): void
    {
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

    public function test_handle_dispatches_add_command(): void
    {
        $entry = new Entry(new Dn('cn=New,dc=example,dc=com'), new Attribute('cn', 'New'));
        $this->subject->handle(new AddCommand($entry));

        self::assertNotNull($this->subject->get(new Dn('cn=New,dc=example,dc=com')));
    }

    public function test_handle_dispatches_delete_command(): void
    {
        $this->subject->handle(new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')));

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_handle_dispatches_update_command(): void
    {
        $this->subject->handle(new UpdateCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            [new Change(Change::TYPE_REPLACE, 'userPassword', 'newpassword')],
        ));

        self::assertSame(
            ['newpassword'],
            $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'))?->get('userPassword')?->getValues(),
        );
    }

    public function test_handle_dispatches_move_command(): void
    {
        $this->subject->handle(new MoveCommand(
            new Dn('cn=Alice,dc=example,dc=com'),
            Rdn::create('cn=Alicia'),
            true,
            null,
        ));

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
        self::assertNotNull($this->subject->get(new Dn('cn=Alicia,dc=example,dc=com')));
    }
}
