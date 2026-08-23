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
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolationDisposition;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class WritableStorageBackendTest extends TestCase
{
    use ServerContainerTrait;

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
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('userPassword', 'secret'),
        );
        $this->bob = new Entry(
            new Dn('cn=Bob,ou=People,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Bob'),
        );

        $this->subject = $this->backendFor(new InMemoryStorage([
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

    public function test_atomic_update_derives_changes_from_the_current_state(): void
    {
        $dn = new Dn('cn=Alice,dc=example,dc=com');
        $append = static fn(string $value): callable => static fn(Entry $entry): array => [
            Change::replace(
                'pwdFailureTime',
                ...[
                    ...($entry->get('pwdFailureTime')?->getValues() ?? []),
                    $value,
                ],
            ),
        ];

        $this->subject->atomicUpdate($dn, $this->systemContext(), $append('20260520120000Z'));
        $this->subject->atomicUpdate($dn, $this->systemContext(), $append('20260520120500Z'));

        self::assertSame(
            ['20260520120000Z', '20260520120500Z'],
            array_values($this->subject->get($dn)?->get('pwdFailureTime')?->getValues() ?? []),
        );
    }

    public function test_atomic_update_is_a_no_op_when_the_entry_is_absent(): void
    {
        $dn = new Dn('cn=Ghost,dc=example,dc=com');

        $this->subject->atomicUpdate(
            $dn,
            $this->systemContext(),
            static fn(Entry $entry): array => [Change::replace('cn', 'ghost')],
        );

        self::assertNull($this->subject->get($dn));
    }

    public function test_atomic_update_is_a_no_op_when_no_changes_are_computed(): void
    {
        $dn = new Dn('cn=Alice,dc=example,dc=com');

        $this->subject->atomicUpdate(
            $dn,
            $this->systemContext(),
            static fn(Entry $entry): array => [],
        );

        self::assertNull($this->subject->get($dn)?->get('pwdFailureTime'));
    }

    public function test_search_base_scope_returns_only_base(): void
    {
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useBaseScope();
        $entries = iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries);

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
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSingleLevelScope();
        $entries = iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries);

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
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $entries = iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries);

        $dns = array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            $entries,
        );

        self::assertContains(
            'dc=example,dc=com',
            $dns,
        );
        self::assertContains(
            'cn=Alice,dc=example,dc=com',
            $dns,
        );
        self::assertContains(
            'cn=Bob,ou=People,dc=example,dc=com',
            $dns,
        );
        self::assertCount(
            3,
            $entries,
        );
    }

    public function test_search_base_scope_throws_no_such_object_when_base_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('cn=Missing,dc=example,dc=com')
            ->useBaseScope();
        $this->subject->search($request, SubentryVisibility::All);
    }

    public function test_search_single_level_throws_no_such_object_when_base_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('cn=Missing,dc=example,dc=com')
            ->useSingleLevelScope();
        $this->subject->search($request, SubentryVisibility::All);
    }

    public function test_search_subtree_throws_no_such_object_when_base_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('cn=Missing,dc=example,dc=com')
            ->useSubtreeScope();
        $this->subject->search($request, SubentryVisibility::All);
    }

    public function test_add_stores_entry(): void
    {
        $entry = new Entry(new Dn('cn=New,dc=example,dc=com'), new Attribute('cn', 'New'));
        $this->subject->add(
            new AddCommand($entry),
            $this->context(),
        );

        self::assertNotNull($this->subject->get(new Dn('cn=New,dc=example,dc=com')));
    }

    public function test_add_throws_entry_already_exists(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->subject->add(
            new AddCommand($this->alice),
            $this->context(),
        );
    }

    public function test_add_throws_no_such_object_when_parent_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $entry = new Entry(new Dn('cn=New,ou=Missing,dc=example,dc=com'), new Attribute('cn', 'New'));
        $this->subject->add(
            new AddCommand($entry),
            $this->context(),
        );
    }

    public function test_add_allows_root_naming_context_entry_for_system_context(): void
    {
        $backend = $this->fromContainer(WritableStorageBackend::class);
        $root = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));
        $backend->add(
            new AddCommand($root),
            $this->systemContext(),
        );

        self::assertNotNull($backend->get(new Dn('dc=example,dc=com')));
    }

    public function test_add_refuses_root_naming_context_entry_for_non_system_context(): void
    {
        $backend = $this->fromContainer(WritableStorageBackend::class);
        $root = new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $backend->add(
            new AddCommand($root),
            $this->context(),
        );
    }

    public function test_add_refuses_single_rdn_root_entry_for_non_system_context(): void
    {
        $backend = $this->fromContainer(WritableStorageBackend::class);
        $root = new Entry(new Dn('dc=com'), new Attribute('dc', 'com'));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $backend->add(
            new AddCommand($root),
            $this->context(),
        );
    }

    public function test_delete_removes_entry(): void
    {
        $this->subject->delete(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
            $this->context(),
        );

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_delete_throws_no_such_object_for_missing_entry(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->delete(
            new DeleteCommand(new Dn('cn=Nobody,dc=example,dc=com')),
            $this->context(),
        );
    }

    public function test_delete_throws_not_allowed_on_non_leaf_when_entry_has_subordinates(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NOT_ALLOWED_ON_NON_LEAF);

        // dc=example,dc=com has cn=Alice as a direct child — cannot be deleted
        $this->subject->delete(
            new DeleteCommand(new Dn('dc=example,dc=com')),
            $this->context(),
        );
    }

    public function test_delete_throws_unwilling_to_perform_when_parent_is_not_in_storage(): void
    {
        $leaf = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
        );
        $backend = $this->backendFor(new InMemoryStorage([$leaf]));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $backend->delete(
            new DeleteCommand(new Dn('dc=example,dc=com')),
            $this->context(),
        );
    }

    public function test_move_throws_unwilling_to_perform_when_parent_is_not_in_storage(): void
    {
        $leaf = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
        );
        $backend = $this->backendFor(new InMemoryStorage([$leaf]));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $backend->move(
            new MoveCommand(
                new Dn('dc=example,dc=com'),
                Rdn::create('dc=renamed'),
                true,
                null,
            ),
            $this->context(),
        );
    }

    public function test_delete_allows_entries_whose_parent_is_in_storage(): void
    {
        $base = new Entry(
            new Dn('dc=example,dc=com'),
            new Attribute('dc', 'example'),
        );
        $leaf = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );
        $backend = $this->backendFor(new InMemoryStorage([$base, $leaf]));

        $backend->delete(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
            $this->context(),
        );

        self::assertNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_update_add_attribute_value(): void
    {
        $this->subject->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [new Change(Change::TYPE_ADD, 'mail', 'alice@example.com')],
            ),
            $this->context(),
        );

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertTrue($entry->get('mail')?->has('alice@example.com'));
    }

    public function test_update_add_value_to_existing_attribute(): void
    {
        $this->subject->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [new Change(Change::TYPE_ADD, 'cn', 'Alicia')],
            ),
            $this->context(),
        );

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNotNull($entry);

        $cn = $entry->get('cn');
        self::assertNotNull($cn);
        self::assertTrue($cn->has('Alice'));
        self::assertTrue($cn->has('Alicia'));
    }

    public function test_update_replace_attribute_value(): void
    {
        $this->subject->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [new Change(Change::TYPE_REPLACE, 'userPassword', 'newpassword')],
            ),
            $this->context(),
        );

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertSame(
            ['newpassword'],
            $entry->get('userPassword')?->getValues(),
        );
    }

    public function test_update_delete_attribute(): void
    {
        $this->subject->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [new Change(Change::TYPE_DELETE, 'userPassword')],
            ),
            $this->context(),
        );

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNull($entry?->get('userPassword'));
    }

    public function test_update_delete_specific_attribute_value(): void
    {
        $this->subject->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [new Change(Change::TYPE_DELETE, 'userPassword', 'secret')],
            ),
            $this->context(),
        );

        $entry = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertFalse($entry?->get('userPassword')?->has('secret') ?? false);
    }

    public function test_update_replace_with_no_values_clears_attribute(): void
    {
        $this->subject->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [new Change(Change::TYPE_REPLACE, 'userPassword')],
            ),
            $this->context(),
        );

        self::assertNull(
            $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'))?->get('userPassword'),
        );
    }

    public function test_update_throws_no_such_object_for_missing_entry(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->update(
            new UpdateCommand(
                new Dn('cn=Nobody,dc=example,dc=com'),
                [new Change(Change::TYPE_REPLACE, 'cn', 'Nobody')],
            ),
            $this->context(),
        );
    }

    public function test_move_renames_entry(): void
    {
        $this->subject->move(
            new MoveCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                Rdn::create('cn=Alicia'),
                true,
                null,
            ),
            $this->context(),
        );

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
        self::assertNotNull($this->subject->get(new Dn('cn=Alicia,dc=example,dc=com')));
    }

    public function test_move_creates_new_rdn_attribute_when_it_does_not_exist_in_entry(): void
    {
        // Alice has no 'uid' attribute; renaming to uid=alice should create it.
        $this->subject->move(
            new MoveCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                Rdn::create('uid=alice'),
                false,
                null,
            ),
            $this->context(),
        );

        $entry = $this->subject->get(new Dn('uid=alice,dc=example,dc=com'));

        self::assertNotNull($entry);
        self::assertTrue($entry->get('uid')?->has('alice'));
    }

    public function test_move_to_new_parent(): void
    {
        $ou = new Entry(new Dn('ou=People,dc=example,dc=com'), new Attribute('ou', 'People'));
        $this->subject->add(
            new AddCommand($ou),
            $this->context(),
        );

        $this->subject->move(
            new MoveCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                Rdn::create('cn=Alice'),
                false,
                new Dn('ou=People,dc=example,dc=com'),
            ),
            $this->context(),
        );

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
        self::assertNotNull($this->subject->get(new Dn('cn=Alice,ou=People,dc=example,dc=com')));
    }

    public function test_move_throws_no_such_object_for_missing_entry(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->move(
            new MoveCommand(
                new Dn('cn=Nobody,dc=example,dc=com'),
                Rdn::create('cn=Ghost'),
                true,
                null,
            ),
            $this->context(),
        );
    }

    public function test_move_relocates_an_entry_that_has_children(): void
    {
        $this->addPeopleOu();

        $this->subject->move(
            $this->renamePeopleToStaff(),
            $this->context(),
        );

        self::assertNotNull($this->subject->get(new Dn('ou=staff,dc=example,dc=com')));
        self::assertNull($this->subject->get(new Dn('ou=people,dc=example,dc=com')));
    }

    public function test_move_takes_the_descendants_of_the_entry_with_it(): void
    {
        $this->addPeopleOu();

        $this->subject->move(
            $this->renamePeopleToStaff(),
            $this->context(),
        );

        self::assertNotNull($this->subject->get(new Dn('cn=bob,ou=staff,dc=example,dc=com')));
        self::assertNull($this->subject->get(new Dn('cn=bob,ou=people,dc=example,dc=com')));
    }

    public function test_move_refuses_relocating_an_entry_beneath_itself(): void
    {
        $this->addPeopleOu();

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->subject->move(
            new MoveCommand(
                new Dn('ou=People,dc=example,dc=com'),
                Rdn::create('ou=Staff'),
                true,
                new Dn('cn=Bob,ou=People,dc=example,dc=com'),
            ),
            $this->context(),
        );
    }

    public function test_move_refuses_a_target_that_already_holds_subordinates(): void
    {
        $this->addPeopleOu();
        $this->subject->add(
            new AddCommand(new Entry(
                new Dn('cn=Orphan,ou=Staff,dc=example,dc=com'),
                new Attribute('cn', 'Orphan'),
            )),
            $this->systemContext(),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->subject->move(
            $this->renamePeopleToStaff(),
            $this->context(),
        );
    }

    public function test_move_throws_no_such_object_when_new_superior_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->move(
            new MoveCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                Rdn::create('cn=Alice'),
                false,
                new Dn('ou=Missing,dc=example,dc=com'),
            ),
            $this->context(),
        );
    }

    public function test_move_throws_entry_already_exists_when_target_dn_exists(): void
    {
        $alicia = new Entry(new Dn('cn=Alicia,dc=example,dc=com'), new Attribute('cn', 'Alicia'));
        $backend = $this->backendFor(new InMemoryStorage([
            $this->base,
            $this->alice,
            $alicia,
        ]));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $backend->move(
            new MoveCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                Rdn::create('cn=Alicia'),
                true,
                null,
            ),
            $this->context(),
        );
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

    public function test_search_converts_time_limit_exception_to_operation_exception(): void
    {
        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('exists')->willReturn(true);
        $storage->method('list')->willReturn(
            new EntryStream($this->makeTimeLimitStream()),
        );

        $subject = $this->backendFor($storage);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::TIME_LIMIT_EXCEEDED);

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSingleLevelScope();
        iterator_to_array($subject->search($request, SubentryVisibility::All)->entries);
    }

    public function test_search_trips_lookthrough_limit_when_examined_exceeds_cap(): void
    {
        $subject = $this->backendFor(
            new InMemoryStorage([$this->base, $this->alice, $this->bob]),
            TestServerOptions::unvalidatedCore()
                ->setMaxSearchLookthrough(2),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        iterator_to_array($subject->search($request, SubentryVisibility::All)->entries);
    }

    public function test_search_does_not_trip_lookthrough_limit_within_cap(): void
    {
        $subject = $this->backendFor(
            new InMemoryStorage([$this->base, $this->alice, $this->bob]),
            TestServerOptions::unvalidatedCore()
                ->setMaxSearchLookthrough(100),
        );

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();

        self::assertCount(
            3,
            iterator_to_array($subject->search($request, SubentryVisibility::All)->entries),
        );
    }

    public function test_search_returns_alias_base_when_base_deref_requested(): void
    {
        $subject = $this->backendFor(new InMemoryStorage([
            $this->base,
            $this->alice,
            $this->aliasEntry(),
        ]));

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('cn=ref,dc=example,dc=com')
            ->useBaseScope()
            ->setDereferenceAliases(SearchRequest::DEREF_FINDING_BASE_OBJECT);
        $entries = iterator_to_array($subject->search($request, SubentryVisibility::All)->entries);

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=ref,dc=example,dc=com',
            array_values($entries)[0]->getDn()->toString(),
        );
    }

    public function test_search_returns_alias_base_when_deref_never(): void
    {
        $subject = $this->backendFor(new InMemoryStorage([
            $this->base,
            $this->alice,
            $this->aliasEntry(),
        ]));

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('cn=ref,dc=example,dc=com')
            ->useBaseScope()
            ->setDereferenceAliases(SearchRequest::DEREF_NEVER);
        $entries = iterator_to_array($subject->search($request, SubentryVisibility::All)->entries);

        self::assertCount(1, $entries);
        self::assertSame(
            'cn=ref,dc=example,dc=com',
            array_values($entries)[0]->getDn()->toString(),
        );
    }

    /**
     * A deliberate deviation from RFC 4511 4.5.1.3, which has an alias found in scope replaced by the entry it names
     * and the search continued in that entry's subtree.
     *
     * Implementing full search dereferencing is not practical, but we shouldn't fail a search when any alias shows up
     * in it. This seems like reasonable behavior, though it's different from what the RFC specifies. But other
     * implementations already handle aliases in different ways.
     */
    public function test_search_returns_alias_in_subtree_when_in_search_deref_requested(): void
    {
        $subject = $this->backendFor(new InMemoryStorage([
            $this->base,
            $this->alice,
            $this->aliasEntry(),
        ]));

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope()
            ->setDereferenceAliases(SearchRequest::DEREF_IN_SEARCHING);
        $dns = array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            array_values(iterator_to_array($subject->search($request, SubentryVisibility::All)->entries)),
        );

        self::assertContains('cn=ref,dc=example,dc=com', $dns);
    }

    public function test_search_returns_alias_in_subtree_when_deref_never(): void
    {
        $subject = $this->backendFor(new InMemoryStorage([
            $this->base,
            $this->alice,
            $this->aliasEntry(),
        ]));

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope()
            ->setDereferenceAliases(SearchRequest::DEREF_NEVER);
        $dns = array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            iterator_to_array($subject->search($request, SubentryVisibility::All)->entries),
        );

        self::assertContains(
            'cn=ref,dc=example,dc=com',
            $dns,
        );
    }

    public function test_search_succeeds_with_deref_always_when_no_aliases_present(): void
    {
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope()
            ->setDereferenceAliases(SearchRequest::DEREF_ALWAYS);

        self::assertCount(
            3,
            iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries),
        );
    }

    public function test_add_converts_storage_io_exception_to_unavailable_operation_exception(): void
    {
        $ioException = new StorageIoException('Unable to publish the storage update.');
        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('atomic')
            ->willThrowException($ioException);

        $subject = $this->backendFor($storage);

        try {
            $subject->add(
                new AddCommand(new Entry(
                    new Dn('cn=New,dc=example,dc=com'),
                    new Attribute('cn', 'New'),
                )),
                $this->context(),
            );
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
            self::assertSame(
                'The backend storage is currently unavailable.',
                $e->getMessage(),
            );
            self::assertSame(
                $ioException,
                $e->getPrevious(),
            );
        }
    }

    public function test_search_returns_empty_stream_when_storage_rejects_filter_attribute(): void
    {
        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('exists')
            ->willReturn(true);
        $storage->method('list')
            ->willThrowException(new InvalidAttributeException(
                'Attribute description "bogus attr" is not a valid RFC 4512 attribute description.',
            ));

        $subject = $this->backendFor($storage);

        $request = (new SearchRequest(new EqualityFilter('bogus attr', 'x')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();

        $stream = $subject->search($request, SubentryVisibility::All);

        self::assertSame(
            [],
            iterator_to_array($stream->entries),
        );
    }

    public function test_delete_converts_storage_io_exception_to_unavailable_operation_exception(): void
    {
        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('atomic')
            ->willThrowException(new StorageIoException('Unable to acquire exclusive lock on the storage backend.'));

        $subject = $this->backendFor($storage);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNAVAILABLE);
        self::expectExceptionMessage('The backend storage is currently unavailable.');

        $subject->delete(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
            $this->context(),
        );
    }

    public function test_update_converts_storage_io_exception_to_unavailable_operation_exception(): void
    {
        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('atomic')
            ->willThrowException(new StorageIoException('Unable to stage the storage update.'));

        $subject = $this->backendFor($storage);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNAVAILABLE);
        self::expectExceptionMessage('The backend storage is currently unavailable.');

        $subject->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [new Change(Change::TYPE_REPLACE, 'cn', 'Alicia')],
            ),
            $this->context(),
        );
    }

    public function test_move_converts_storage_io_exception_to_unavailable_operation_exception(): void
    {
        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        // The entry and its parent are read before the write opens, so both must resolve to reach atomic().
        $storage->method('find')
            ->willReturn($this->alice);
        $storage->method('exists')
            ->willReturn(true);
        $storage->method('list')
            ->willReturn(new EntryStream($this->makeGenerator($this->alice)));
        $storage->method('atomic')
            ->willThrowException(new StorageIoException('Unable to publish the storage update.'));

        $subject = $this->backendFor($storage);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNAVAILABLE);
        self::expectExceptionMessage('The backend storage is currently unavailable.');

        $subject->move(
            new MoveCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                Rdn::create('cn=Alicia'),
                true,
                null,
            ),
            $this->context(),
        );
    }

    public function test_supports_returns_false_for_unknown_request(): void
    {
        $unknown = $this->createMock(WriteRequestInterface::class);

        self::assertFalse($this->subject->supports($unknown));
    }

    public function test_handle_dispatches_add_command(): void
    {
        $entry = new Entry(new Dn('cn=New,dc=example,dc=com'), new Attribute('cn', 'New'));
        $this->subject->handle(
            new AddCommand($entry),
            $this->context(),
        );

        self::assertNotNull($this->subject->get(new Dn('cn=New,dc=example,dc=com')));
    }

    public function test_handle_dispatches_delete_command(): void
    {
        $this->subject->handle(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
            $this->context(),
        );

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_handle_dispatches_update_command(): void
    {
        $this->subject->handle(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [new Change(Change::TYPE_REPLACE, 'userPassword', 'newpassword')],
            ),
            $this->context(),
        );

        self::assertSame(
            ['newpassword'],
            $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'))?->get('userPassword')?->getValues(),
        );
    }

    public function test_handle_dispatches_move_command(): void
    {
        $this->subject->handle(
            new MoveCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                Rdn::create('cn=Alicia'),
                true,
                null,
            ),
            $this->context(),
        );

        self::assertNull($this->subject->get(new Dn('cn=Alice,dc=example,dc=com')));
        self::assertNotNull($this->subject->get(new Dn('cn=Alicia,dc=example,dc=com')));
    }

    #[DataProvider('provideMaxSearchTimeLimitCases')]
    public function test_max_search_time_limit_computes_effective_time_limit(
        int $serverMax,
        int $requestLimit,
        int $expectedLimit,
    ): void {
        $capturedOptions = null;

        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('exists')->willReturn(true);
        $storage
            ->method('list')
            ->willReturnCallback(function (StorageListOptions $opts) use (&$capturedOptions): EntryStream {
                $capturedOptions = $opts;

                return new EntryStream($this->makeGenerator());
            });

        $subject = $this->backendFor(
            $storage,
            TestServerOptions::unvalidatedCore()
                ->setMaxSearchTimeLimit($serverMax),
        );

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSingleLevelScope()
            ->timeLimit($requestLimit);

        iterator_to_array($subject->search($request, SubentryVisibility::All)->entries);

        self::assertSame(
            $expectedLimit,
            $capturedOptions?->timeLimit,
        );
    }

    /**
     * @return array<string, array{int, int, int}>
     */
    public static function provideMaxSearchTimeLimitCases(): array
    {
        return [
            'server cap applies when client requests no limit' => [5, 0, 5],
            'server cap overrides when client exceeds it'      => [5, 10, 5],
            'client limit used when below server max'          => [5, 3, 3],
            'no server cap preserves client limit'             => [0, 10, 10],
        ];
    }

    public function test_add_with_validator_rejects_invalid_entry(): void
    {
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base]),
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $backend->add(
            new AddCommand(new Entry(
                new Dn('cn=Invalid,dc=example,dc=com'),
                new Attribute('cn', 'Invalid'),
            )),
            $this->context(),
        );
    }

    public function test_add_with_validator_accepts_valid_entry(): void
    {
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base]),
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        );

        $backend->add(
            new AddCommand(new Entry(
                new Dn('cn=Alice,dc=example,dc=com'),
                new Attribute('objectClass', 'top', 'person'),
                new Attribute('cn', 'Alice'),
                new Attribute('sn', 'Smith'),
            )),
            $this->context(),
        );

        self::assertNotNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_update_with_validator_rejects_invalid_modification(): void
    {
        $valid = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base, $valid]),
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $backend->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
            ),
            $this->context(),
        );
    }

    public function test_add_with_lenient_validator_allows_invalid_entry_and_records_violation(): void
    {
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base]),
            TestServerOptions::validatedCore(SchemaValidationMode::Lenient),
        );
        $violations = new SchemaViolations();

        $backend->add(
            new AddCommand(new Entry(
                new Dn('cn=Invalid,dc=example,dc=com'),
                new Attribute('cn', 'Invalid'),
            )),
            new WriteContext(
                new AnonToken(),
                new ControlBag(),
                schemaViolations: $violations,
            ),
        );

        self::assertNotNull(
            $backend->get(new Dn('cn=Invalid,dc=example,dc=com')),
        );
        self::assertCount(
            1,
            $violations->all(),
        );
        self::assertSame(
            ResultCode::OBJECT_CLASS_VIOLATION,
            $violations->all()[0]->exception->getCode(),
        );
        self::assertSame(
            SchemaViolationDisposition::RelaxedByPolicy,
            $violations->all()[0]->disposition,
        );
    }

    public function test_update_with_lenient_validator_allows_invalid_modification_and_records_violation(): void
    {
        $valid = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base, $valid]),
            TestServerOptions::validatedCore(SchemaValidationMode::Lenient),
        );
        $violations = new SchemaViolations();

        $backend->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
            ),
            new WriteContext(
                new AnonToken(),
                new ControlBag(),
                schemaViolations: $violations,
            ),
        );

        $stored = $backend->get(new Dn('cn=Alice,dc=example,dc=com'));
        self::assertSame(
            '20240101000000Z',
            $stored?->get('createTimestamp')?->firstValue(),
        );
        self::assertCount(
            1,
            $violations->all(),
        );
        self::assertSame(
            ResultCode::CONSTRAINT_VIOLATION,
            $violations->all()[0]->exception->getCode(),
        );
        self::assertSame(
            SchemaViolationDisposition::RelaxedByPolicy,
            $violations->all()[0]->disposition,
        );
    }

    public function test_relax_control_allows_invalid_add_under_strict_validator(): void
    {
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base]),
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        );
        $violations = new SchemaViolations();

        $backend->add(
            new AddCommand(new Entry(
                new Dn('cn=Invalid,dc=example,dc=com'),
                new Attribute('cn', 'Invalid'),
            )),
            new WriteContext(
                new AnonToken(),
                new ControlBag(Controls::relaxRules()),
                schemaViolations: $violations,
            ),
        );

        self::assertNotNull(
            $backend->get(new Dn('cn=Invalid,dc=example,dc=com')),
        );
        self::assertSame(
            SchemaViolationDisposition::RelaxedByControl,
            $violations->all()[0]->disposition,
        );
    }

    public function test_relax_control_does_not_relax_invalid_attribute_syntax(): void
    {
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base]),
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        );
        $violations = new SchemaViolations();

        $code = null;
        try {
            $backend->add(
                new AddCommand(new Entry(
                    new Dn('cn=Alice,dc=example,dc=com'),
                    new Attribute('objectClass', 'top', 'person'),
                    new Attribute('cn', 'Alice'),
                    new Attribute('sn', 'Smith'),
                    new Attribute('seeAlso', 'not a dn'),
                )),
                new WriteContext(
                    new AnonToken(),
                    new ControlBag(Controls::relaxRules()),
                    schemaViolations: $violations,
                ),
            );
        } catch (OperationException $e) {
            $code = $e->getCode();
        }

        self::assertSame(
            ResultCode::INVALID_ATTRIBUTE_SYNTAX,
            $code,
        );
        self::assertNull(
            $backend->get(new Dn('cn=Alice,dc=example,dc=com')),
        );
        self::assertSame(
            SchemaViolationDisposition::Rejected,
            $violations->all()[0]->disposition,
        );
    }

    public function test_lenient_validator_does_not_relax_invalid_attribute_syntax(): void
    {
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base]),
            TestServerOptions::validatedCore(SchemaValidationMode::Lenient),
        );
        $violations = new SchemaViolations();

        $code = null;
        try {
            $backend->add(
                new AddCommand(new Entry(
                    new Dn('cn=Alice,dc=example,dc=com'),
                    new Attribute('objectClass', 'top', 'person'),
                    new Attribute('cn', 'Alice'),
                    new Attribute('sn', 'Smith'),
                    new Attribute('seeAlso', 'not a dn'),
                )),
                new WriteContext(
                    new AnonToken(),
                    new ControlBag(),
                    schemaViolations: $violations,
                ),
            );
        } catch (OperationException $e) {
            $code = $e->getCode();
        }

        self::assertSame(
            ResultCode::INVALID_ATTRIBUTE_SYNTAX,
            $code,
        );
        self::assertNull(
            $backend->get(new Dn('cn=Alice,dc=example,dc=com')),
        );
        self::assertSame(
            SchemaViolationDisposition::Rejected,
            $violations->all()[0]->disposition,
        );
    }

    public function test_system_update_bypasses_no_user_modification_check(): void
    {
        $valid = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base, $valid]),
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        );

        $backend->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
            ),
            WriteContext::system(
                new AnonToken(),
                new ControlBag(),
            ),
        );

        $stored = $backend->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertSame(
            '20240101000000Z',
            $stored?->get('createTimestamp')?->firstValue(),
        );
    }

    public function test_system_update_still_enforces_single_valued_attribute(): void
    {
        $valid = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
        );
        $backend = $this->backendFor(
            new InMemoryStorage([$this->base, $valid]),
            TestServerOptions::validatedCore(SchemaValidationMode::Strict),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $backend->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [Change::replace(new Attribute('createTimestamp', '20240101000000Z', '20240202000000Z'))],
            ),
            WriteContext::system(
                new AnonToken(),
                new ControlBag(),
            ),
        );
    }

    public function test_add_sets_operational_attributes_on_entry(): void
    {
        $entry = new Entry(
            new Dn('cn=New,dc=example,dc=com'),
            new Attribute('cn', 'New'),
        );

        $this->subject->add(
            new AddCommand($entry),
            $this->context(),
        );

        $stored = $this->subject->get(new Dn('cn=New,dc=example,dc=com'));

        self::assertNotNull($stored?->get('createTimestamp'));
        self::assertNotNull($stored->get('modifyTimestamp'));
        self::assertNotNull($stored->get('creatorsName'));
        self::assertNotNull($stored->get('modifiersName'));
        self::assertNotNull($stored->get('entryUUID'));
    }

    public function test_update_refreshes_modify_operational_attributes(): void
    {
        $this->subject->update(
            new UpdateCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                [Change::replace(new Attribute('userPassword', 'newSecret'))],
            ),
            $this->context(),
        );

        $updated = $this->subject->get(new Dn('cn=Alice,dc=example,dc=com'));

        self::assertNotNull($updated?->get('modifyTimestamp'));
        self::assertNotNull($updated->get('modifiersName'));
    }

    public function test_move_refreshes_modify_operational_attributes(): void
    {
        $this->subject->move(
            new MoveCommand(
                new Dn('cn=Alice,dc=example,dc=com'),
                Rdn::create('cn=Alicia'),
                true,
                null,
            ),
            $this->context(),
        );

        $moved = $this->subject->get(new Dn('cn=Alicia,dc=example,dc=com'));

        self::assertNotNull($moved?->get('modifyTimestamp'));
        self::assertNotNull($moved->get('modifiersName'));
    }

    public function test_search_with_plus_includes_has_subordinates(): void
    {
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope()
            ->select('+');

        $results = iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries);

        foreach ($results as $entry) {
            self::assertNotNull(
                $entry->get('hasSubordinates'),
                "Entry {$entry->getDn()->toString()} is missing hasSubordinates.",
            );
        }
    }

    public function test_search_with_has_subordinates_by_name_includes_it(): void
    {
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope()
            ->select('hasSubordinates');

        $results = iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries);

        foreach ($results as $entry) {
            self::assertNotNull(
                $entry->get('hasSubordinates'),
                "Entry {$entry->getDn()->toString()} is missing hasSubordinates.",
            );
        }
    }

    public function test_search_without_plus_does_not_include_has_subordinates(): void
    {
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope()
            ->select('cn');

        $results = iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries);

        foreach ($results as $entry) {
            self::assertNull(
                $entry->get('hasSubordinates'),
                "Entry {$entry->getDn()->toString()} must not have hasSubordinates injected.",
            );
        }
    }

    public function test_search_has_subordinates_is_true_for_parent(): void
    {
        // dc=example,dc=com has Alice as a child.
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useBaseScope()
            ->select('+');

        $results = iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries);

        self::assertCount(1, $results);
        self::assertSame(
            'TRUE',
            $results[0]->get('hasSubordinates')?->getValues()[0],
        );
    }

    public function test_search_has_subordinates_is_false_for_leaf(): void
    {
        // Alice has no children.
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('cn=Alice,dc=example,dc=com')
            ->useBaseScope()
            ->select('+');

        $results = iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries);

        self::assertCount(1, $results);
        self::assertSame(
            'FALSE',
            $results[0]->get('hasSubordinates')?->getValues()[0],
        );
    }

    public function test_search_has_subordinates_does_not_mutate_stored_entry(): void
    {
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useBaseScope()
            ->select('+');

        iterator_to_array($this->subject->search($request, SubentryVisibility::All)->entries);

        // Read the stored entry directly — hasSubordinates must not be persisted.
        $stored = $this->subject->get(new Dn('dc=example,dc=com'));

        self::assertNull($stored?->get('hasSubordinates'));
    }

    public function test_no_such_object_on_search_base_carries_matched_dn(): void
    {
        // dc=example,dc=com exists; cn=Missing does not — matchedDn should be dc=example,dc=com
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('cn=Missing,dc=example,dc=com')
            ->useBaseScope();

        try {
            $this->subject->search($request, SubentryVisibility::All);
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                'dc=example,dc=com',
                $e->getMatchedDn()?->toString(),
            );
        }
    }

    public function test_no_such_object_on_search_subtree_carries_matched_dn(): void
    {
        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('cn=Missing,dc=example,dc=com')
            ->useSubtreeScope();

        try {
            $this->subject->search($request, SubentryVisibility::All);
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                'dc=example,dc=com',
                $e->getMatchedDn()?->toString(),
            );
        }
    }

    public function test_no_such_object_on_delete_carries_matched_dn(): void
    {
        try {
            $this->subject->delete(
                new DeleteCommand(new Dn('cn=Nobody,dc=example,dc=com')),
                $this->context(),
            );
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                'dc=example,dc=com',
                $e->getMatchedDn()?->toString(),
            );
        }
    }

    public function test_no_such_object_on_update_carries_matched_dn(): void
    {
        try {
            $this->subject->update(
                new UpdateCommand(
                    new Dn('cn=Nobody,dc=example,dc=com'),
                    [new Change(Change::TYPE_REPLACE, 'cn', 'Nobody')],
                ),
                $this->context(),
            );
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                'dc=example,dc=com',
                $e->getMatchedDn()?->toString(),
            );
        }
    }

    public function test_no_such_object_on_compare_carries_matched_dn(): void
    {
        try {
            $this->subject->compare(
                new Dn('cn=Nobody,dc=example,dc=com'),
                new EqualityFilter('cn', 'Nobody'),
            );
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                'dc=example,dc=com',
                $e->getMatchedDn()?->toString(),
            );
        }
    }

    public function test_no_such_object_on_add_with_missing_parent_carries_matched_dn(): void
    {
        // ou=Missing does not exist; dc=example,dc=com does — matchedDn should be dc=example,dc=com
        try {
            $this->subject->add(
                new AddCommand(new Entry(
                    new Dn('cn=New,ou=Missing,dc=example,dc=com'),
                    new Attribute('cn', 'New'),
                )),
                $this->context(),
            );
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(
                'dc=example,dc=com',
                $e->getMatchedDn()?->toString(),
            );
        }
    }

    public function test_no_such_object_with_no_existing_ancestor_has_null_matched_dn(): void
    {
        $backend = $this->fromContainer(WritableStorageBackend::class);

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('cn=Missing,dc=example,dc=com')
            ->useBaseScope();

        try {
            $backend->search($request, SubentryVisibility::All);
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertNull($e->getMatchedDn());
        }
    }

    public function test_delete_subtree_removes_the_entry_and_all_descendants(): void
    {
        $backend = $this->subtreeBackend();

        $backend->deleteSubtree(
            new DeleteCommand(new Dn('ou=people,dc=example,dc=com')),
            $this->context(),
            static function (Dn $dn): void {},
        );

        self::assertNull($backend->get(new Dn('ou=people,dc=example,dc=com')));
        self::assertNull($backend->get(new Dn('cn=alice,ou=people,dc=example,dc=com')));
        self::assertNull($backend->get(new Dn('cn=bob,ou=people,dc=example,dc=com')));
        self::assertNotNull($backend->get(new Dn('dc=example,dc=com')));
    }

    public function test_delete_subtree_removes_a_deeply_nested_subtree(): void
    {
        $backend = $this->backendFor(new InMemoryStorage([
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            new Entry(new Dn('ou=people,dc=example,dc=com'), new Attribute('ou', 'people')),
            new Entry(new Dn('ou=staff,ou=people,dc=example,dc=com'), new Attribute('ou', 'staff')),
            new Entry(new Dn('cn=deep,ou=staff,ou=people,dc=example,dc=com'), new Attribute('cn', 'deep')),
        ]));

        $backend->deleteSubtree(
            new DeleteCommand(new Dn('ou=people,dc=example,dc=com')),
            $this->context(),
            static function (Dn $dn): void {},
        );

        self::assertNull($backend->get(new Dn('ou=people,dc=example,dc=com')));
        self::assertNull($backend->get(new Dn('ou=staff,ou=people,dc=example,dc=com')));
        self::assertNull($backend->get(new Dn('cn=deep,ou=staff,ou=people,dc=example,dc=com')));
        self::assertNotNull($backend->get(new Dn('dc=example,dc=com')));
    }

    public function test_delete_subtree_authorizes_every_entry(): void
    {
        $backend = $this->subtreeBackend();
        $seen = [];

        $backend->deleteSubtree(
            new DeleteCommand(new Dn('ou=people,dc=example,dc=com')),
            $this->context(),
            static function (Dn $dn) use (&$seen): void {
                $seen[] = $dn->toString();
            },
        );

        sort($seen);
        self::assertSame(
            [
                'cn=alice,ou=people,dc=example,dc=com',
                'cn=bob,ou=people,dc=example,dc=com',
                'ou=people,dc=example,dc=com',
            ],
            $seen,
        );
    }

    public function test_delete_subtree_removes_nothing_when_authorization_is_denied(): void
    {
        $backend = $this->subtreeBackend();

        try {
            $backend->deleteSubtree(
                new DeleteCommand(new Dn('ou=people,dc=example,dc=com')),
                $this->context(),
                static function (Dn $dn): void {
                    if (str_contains($dn->toString(), 'cn=bob')) {
                        throw new OperationException(
                            'denied',
                            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                        );
                    }
                },
            );
            self::fail('Expected OperationException was not thrown.');
        } catch (OperationException $e) {
            self::assertSame(ResultCode::INSUFFICIENT_ACCESS_RIGHTS, $e->getCode());
        }

        self::assertNotNull($backend->get(new Dn('ou=people,dc=example,dc=com')));
        self::assertNotNull($backend->get(new Dn('cn=alice,ou=people,dc=example,dc=com')));
        self::assertNotNull($backend->get(new Dn('cn=bob,ou=people,dc=example,dc=com')));
    }

    public function test_delete_subtree_rejects_a_naming_context_base(): void
    {
        $backend = $this->subtreeBackend();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $backend->deleteSubtree(
            new DeleteCommand(new Dn('dc=example,dc=com')),
            $this->context(),
            static function (Dn $dn): void {},
        );
    }

    public function test_delete_subtree_throws_no_such_object_for_a_missing_base(): void
    {
        $backend = $this->subtreeBackend();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $backend->deleteSubtree(
            new DeleteCommand(new Dn('ou=missing,dc=example,dc=com')),
            $this->context(),
            static function (Dn $dn): void {},
        );
    }

    public function test_delete_subtree_journals_every_entry_with_its_pre_image(): void
    {
        [$backend, $journal] = $this->journalingBackend();
        foreach ([
            new Entry(new Dn('ou=people,dc=example,dc=com'), new Attribute('ou', 'people')),
            new Entry(new Dn('cn=alice,ou=people,dc=example,dc=com'), new Attribute('cn', 'alice')),
            new Entry(new Dn('cn=bob,ou=people,dc=example,dc=com'), new Attribute('cn', 'bob')),
        ] as $entry) {
            $backend->add(
                new AddCommand($entry),
                $this->context(),
            );
        }

        $backend->deleteSubtree(
            new DeleteCommand(new Dn('ou=people,dc=example,dc=com')),
            $this->context(),
            static function (Dn $dn): void {},
        );

        $deletes = array_values(array_filter(
            iterator_to_array($journal->read()),
            static fn(ChangeRecord $record): bool => $record->change->changeType === ChangeType::Delete,
        ));

        self::assertSame(
            [
                'cn=alice,ou=people,dc=example,dc=com',
                'cn=bob,ou=people,dc=example,dc=com',
                'ou=people,dc=example,dc=com',
            ],
            $this->sortedDns($deletes),
        );
        foreach ($deletes as $record) {
            self::assertNotNull($record->change->preImage);
        }
    }

    public function test_add_is_journaled_when_a_recorder_is_set(): void
    {
        [$backend, $journal] = $this->journalingBackend();
        $backend->add(
            new AddCommand(new Entry(new Dn('cn=New,dc=example,dc=com'), new Attribute('cn', 'New'))),
            $this->context(),
        );

        $records = iterator_to_array($journal->read());
        self::assertCount(
            1,
            $records,
        );
        self::assertSame(
            ChangeType::Add,
            $records[0]->change->changeType,
        );
        self::assertNotSame(
            '',
            $records[0]->change->entryUuid,
        );
    }

    public function test_modify_is_journaled(): void
    {
        [$backend, $journal] = $this->journalingBackend();
        $this->seedJournaled($backend, 'cn=New,dc=example,dc=com');

        $backend->update(
            new UpdateCommand(
                new Dn('cn=New,dc=example,dc=com'),
                [new Change(Change::TYPE_ADD, 'mail', 'new@example.com')],
            ),
            $this->context(),
        );

        self::assertSame(
            ChangeType::Modify,
            $this->lastChange($journal)->changeType,
        );
    }

    public function test_delete_is_journaled_with_a_pre_image(): void
    {
        [$backend, $journal] = $this->journalingBackend();
        $this->seedJournaled($backend, 'cn=New,dc=example,dc=com');

        $backend->delete(
            new DeleteCommand(new Dn('cn=New,dc=example,dc=com')),
            $this->context(),
        );

        $change = $this->lastChange($journal);
        self::assertSame(
            ChangeType::Delete,
            $change->changeType,
        );
        self::assertNotNull($change->preImage);
    }

    public function test_modrdn_is_journaled_with_the_previous_dn(): void
    {
        [$backend, $journal] = $this->journalingBackend();
        $this->seedJournaled($backend, 'cn=New,dc=example,dc=com');

        $backend->move(
            new MoveCommand(
                new Dn('cn=New,dc=example,dc=com'),
                Rdn::create('cn=Renamed'),
                true,
                null,
            ),
            $this->context(),
        );

        $change = $this->lastChange($journal);
        self::assertSame(
            ChangeType::ModRdn,
            $change->changeType,
        );
        self::assertSame(
            'cn=New,dc=example,dc=com',
            $change->previousDn?->toString(),
        );
    }

    public function test_subtree_delete_is_journaled_per_entry(): void
    {
        [$backend, $journal] = $this->journalingBackend();
        $this->seedJournaled($backend, 'ou=people,dc=example,dc=com');
        $this->seedJournaled($backend, 'cn=New,ou=people,dc=example,dc=com');

        $backend->deleteSubtree(
            new DeleteCommand(new Dn('ou=people,dc=example,dc=com')),
            $this->context(),
            static fn(): null => null,
        );

        $deletes = array_filter(
            iterator_to_array($journal->read()),
            static fn(ChangeRecord $record): bool => $record->change->changeType === ChangeType::Delete,
        );
        self::assertCount(
            2,
            $deletes,
        );
    }

    public function test_nothing_is_journaled_without_a_recorder(): void
    {
        $journal = new InMemoryChangeJournal();
        $storage = new InMemoryStorage(
            [new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))],
            $journal,
        );
        $backend = $this->backendFor($storage);

        $backend->add(
            new AddCommand(new Entry(new Dn('cn=New,dc=example,dc=com'), new Attribute('cn', 'New'))),
            $this->context(),
        );

        self::assertSame(
            0,
            $journal->latestSeq(),
        );
    }

    /**
     * Validation is opted into by the tests that assert on it, rather than applied to every fixture here.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
    }

    private function aliasEntry(): Entry
    {
        return new Entry(
            new Dn('cn=ref,dc=example,dc=com'),
            new Attribute('objectClass', 'alias'),
            new Attribute('aliasedObjectName', 'cn=Alice,dc=example,dc=com'),
        );
    }

    /**
     * @return array{WritableStorageBackend, InMemoryChangeJournal}
     */
    private function journalingBackend(): array
    {
        $journal = new InMemoryChangeJournal();
        // Seed the naming context directly so only the operations under test are journaled.
        $storage = new InMemoryStorage(
            [new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))],
            $journal,
        );
        $backend = $this->backendFor(
            $storage,
            // A recorder is only wired when a journal is configured and the storage can journal.
            TestServerOptions::unvalidatedCore()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );

        return [$backend, $journal];
    }

    private function seedJournaled(
        WritableStorageBackend $backend,
        string $dn,
    ): void {
        $backend->add(
            new AddCommand(new Entry(
                new Dn($dn),
                new Attribute('objectClass', 'person'),
                new Attribute('cn', 'seed'),
            )),
            $this->context(),
        );
    }

    private function lastChange(InMemoryChangeJournal $journal): PendingChange
    {
        $records = iterator_to_array($journal->read());
        $last = end($records);
        self::assertInstanceOf(
            ChangeRecord::class,
            $last,
        );

        return $last->change;
    }

    private function context(): WriteContext
    {
        return new WriteContext(
            new AnonToken(),
            new ControlBag(),
        );
    }

    private function systemContext(): WriteContext
    {
        return WriteContext::system(
            new AnonToken(),
            new ControlBag(),
        );
    }

    /**
     * The shared fixture puts cn=Bob under this, but leaves the OU itself out.
     */
    private function addPeopleOu(): void
    {
        $this->subject->add(
            new AddCommand(new Entry(
                new Dn('ou=People,dc=example,dc=com'),
                new Attribute('ou', 'People'),
            )),
            $this->context(),
        );
    }

    private function renamePeopleToStaff(): MoveCommand
    {
        return new MoveCommand(
            new Dn('ou=People,dc=example,dc=com'),
            Rdn::create('ou=Staff'),
            true,
            null,
        );
    }

    /**
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     */
    private function makeTimeLimitStream(): Generator
    {
        yield new Entry(new Dn('dc=example,dc=com'));

        throw new TimeLimitExceededException();
    }

    private function subtreeBackend(): WritableStorageBackend
    {
        return $this->backendFor(new InMemoryStorage([
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            new Entry(new Dn('ou=people,dc=example,dc=com'), new Attribute('ou', 'people')),
            new Entry(new Dn('cn=alice,ou=people,dc=example,dc=com'), new Attribute('cn', 'alice')),
            new Entry(new Dn('cn=bob,ou=people,dc=example,dc=com'), new Attribute('cn', 'bob')),
        ]));
    }

    /**
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     */
    private function makeGenerator(Entry ...$entries): Generator
    {
        foreach ($entries as $entry) {
            yield $entry;
        }

        return null;
    }

    /**
     * @param list<ChangeRecord> $records
     *
     * @return list<string>
     */
    private function sortedDns(array $records): array
    {
        $dns = array_map(
            static fn(ChangeRecord $record): string => $record->change->dn->toString(),
            $records,
        );
        sort($dns);

        return $dns;
    }
}
