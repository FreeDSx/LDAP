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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteSubtreeCommand;
use FreeDSx\Ldap\Server\Backend\Write\Operation\DeleteSubtreeHandler;
use FreeDSx\Ldap\Server\Backend\Write\Operation\EntryPlacementGuard;
use FreeDSx\Ldap\Server\Backend\Write\Operation\LockedEntryAccess;
use FreeDSx\Ldap\Server\Backend\Write\Operation\SubtreeChunkRemover;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Clock\Sleeper\BlockingSleeper;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Write\WriteHandlerTestTrait;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;

final class DeleteSubtreeHandlerTest extends TestCase
{
    use WriteHandlerTestTrait;

    protected function setUp(): void
    {
        $this->subtreeGraph();
    }

    public function test_it_removes_the_entry_and_all_descendants(): void
    {
        $this->deleteSubtree('ou=people,dc=example,dc=com');

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=alice,ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=bob,ou=people,dc=example,dc=com'));
        self::assertNotNull($this->find('dc=example,dc=com'));
    }

    public function test_it_reaches_a_deeply_nested_subtree(): void
    {
        $this->subtreeGraph(EntryFixture::inMemoryStorage(
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            new Entry(new Dn('ou=people,dc=example,dc=com'), new Attribute('ou', 'people')),
            new Entry(new Dn('ou=staff,ou=people,dc=example,dc=com'), new Attribute('ou', 'staff')),
            new Entry(new Dn('cn=deep,ou=staff,ou=people,dc=example,dc=com'), new Attribute('cn', 'deep')),
        ));

        $this->deleteSubtree('ou=people,dc=example,dc=com');

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNull($this->find('ou=staff,ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=deep,ou=staff,ou=people,dc=example,dc=com'));
        self::assertNotNull($this->find('dc=example,dc=com'));
    }

    public function test_it_refuses_a_naming_context_base(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->deleteSubtree('dc=example,dc=com');
    }

    public function test_it_refuses_a_base_that_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->deleteSubtree('ou=missing,dc=example,dc=com');
    }

    public function test_it_journals_every_entry_with_its_pre_image(): void
    {
        $journal = $this->journaledGraph();
        foreach ([
            'ou=people,dc=example,dc=com',
            'cn=alice,ou=people,dc=example,dc=com',
            'cn=bob,ou=people,dc=example,dc=com',
        ] as $dn) {
            $this->seed($dn);
        }

        $this->deleteSubtree('ou=people,dc=example,dc=com');

        $deletes = array_values(array_filter(
            iterator_to_array($journal->read()),
            static fn(ChangeRecord $record): bool => $record->change->changeType === ChangeType::Delete,
        ));
        $dns = array_map(
            static fn(ChangeRecord $record): string => $record->change->dn->toString(),
            $deletes,
        );
        sort($dns);

        self::assertSame(
            [
                'cn=alice,ou=people,dc=example,dc=com',
                'cn=bob,ou=people,dc=example,dc=com',
                'ou=people,dc=example,dc=com',
            ],
            $dns,
        );
        foreach ($deletes as $record) {
            self::assertNotNull($record->change->preImage);
        }
    }

    public function test_it_journals_the_base_after_its_children(): void
    {
        $journal = $this->journaledGraph();
        foreach ([
            'ou=people,dc=example,dc=com',
            'ou=staff,ou=people,dc=example,dc=com',
            'cn=alice,ou=staff,ou=people,dc=example,dc=com',
        ] as $dn) {
            $this->seed($dn);
        }

        $this->deleteSubtree('ou=people,dc=example,dc=com');

        self::assertSame(
            [
                'cn=alice,ou=staff,ou=people,dc=example,dc=com',
                'ou=staff,ou=people,dc=example,dc=com',
                'ou=people,dc=example,dc=com',
            ],
            array_values(array_map(
                static fn(ChangeRecord $record): string => $record->change->dn->toString(),
                array_filter(
                    iterator_to_array($journal->read()),
                    static fn(ChangeRecord $record): bool => $record->change->changeType === ChangeType::Delete,
                ),
            )),
        );
    }

    public function test_a_failure_partway_through_keeps_the_base_and_leaves_no_orphans(): void
    {
        $this->graphWithFailingJournal(1000);

        try {
            $this->deleteSubtree('ou=people,dc=example,dc=com');
            self::fail('The journal failure should have failed the delete.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
            self::assertSame(
                1000,
                $this->deletedIn($e->controls()),
            );
        }

        self::assertNotNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=child1,ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=child1000,ou=people,dc=example,dc=com'));
        $this->assertNoOrphans();
    }

    public function test_a_subtree_within_one_transaction_is_removed_atomically(): void
    {
        $this->graphWithFailingJournal(999);

        try {
            $this->deleteSubtree('ou=people,dc=example,dc=com');
            self::fail('The journal failure should have failed the delete.');
        } catch (StorageIoException $e) {
            self::assertSame(
                'The journal is unavailable.',
                $e->getMessage(),
            );
        }

        self::assertNotNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNotNull($this->find('cn=child1,ou=people,dc=example,dc=com'));
        self::assertNotNull($this->find('cn=child999,ou=people,dc=example,dc=com'));
    }

    public function test_a_completed_delete_reports_every_entry_it_removed(): void
    {
        $context = $this->context();

        $this->deleteSubtreeWith(
            $this->handlerWith(3),
            $context,
        );

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
        self::assertSame(
            3,
            $this->deletedIn($context->responseControls()),
        );
    }

    public function test_a_subtree_larger_than_the_limit_stops_short_of_the_base(): void
    {
        try {
            $this->deleteSubtreeWith(
                $this->handlerWith(2),
                $this->context(),
            );
            self::fail('The limit should have stopped the delete.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
            self::assertSame(
                2,
                $this->deletedIn($e->controls()),
            );
        }

        self::assertNotNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=alice,ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=bob,ou=people,dc=example,dc=com'));
    }

    public function test_a_resubmitted_delete_finishes_what_the_limit_stopped(): void
    {
        $handler = $this->handlerWith(2);
        $context = $this->context();

        try {
            $this->deleteSubtreeWith(
                $handler,
                $this->context(),
            );
        } catch (OperationException) {
        }
        $this->deleteSubtreeWith(
            $handler,
            $context,
        );

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
        self::assertSame(
            1,
            $this->deletedIn($context->responseControls()),
        );
    }

    public function test_a_system_write_is_not_held_to_the_limit(): void
    {
        $this->deleteSubtreeWith(
            $this->handlerWith(1),
            $this->systemContext(),
        );

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNull($this->find('cn=alice,ou=people,dc=example,dc=com'));
    }

    public function test_a_subtree_that_keeps_gaining_children_gives_up_as_busy(): void
    {
        $strays = 0;
        $lister = $this->createMock(ListEntryInterface::class);
        $lister
            ->method('list')
            ->willReturnCallback(fn(StorageListOptions $options): EntryStream => $this->storage->list($options));
        $lister
            ->method('childDns')
            ->willReturnCallback(static function () use (&$strays): array {
                $strays++;

                return ["cn=stray{$strays},ou=people,dc=example,dc=com"];
            });

        try {
            $this->deleteSubtreeWith(
                $this->handlerWith(
                    25_000,
                    new SubtreeEnumerator($lister),
                ),
                $this->context(),
            );
            self::fail('A subtree that never stops changing should have been given up on.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::BUSY,
                $e->getCode(),
            );
            self::assertSame(
                2,
                $this->deletedIn($e->controls()),
            );
        }

        self::assertNotNull($this->find('ou=people,dc=example,dc=com'));
    }

    public function test_a_subtree_removed_in_one_transaction_never_pauses(): void
    {
        $sleeper = $this->createMock(SleeperInterface::class);
        $sleeper
            ->expects(self::never())
            ->method('sleep');

        $this->deleteSubtreeWith(
            $this->handlerWith(
                3,
                sleeper: $sleeper,
            ),
            $this->context(),
        );
    }

    public function test_the_delete_pauses_between_transactions_to_let_other_operations_in(): void
    {
        $this->subtreeGraph($this->peopleWithChildren(1000));
        $sleeper = $this->createMock(SleeperInterface::class);
        $sleeper
            ->expects(self::once())
            ->method('sleep')
            ->with(self::greaterThan(0.0));

        $this->deleteSubtreeWith(
            $this->handlerWith(
                25_000,
                sleeper: $sleeper,
            ),
            $this->context(),
        );

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
    }

    public function test_a_completed_delete_is_recorded(): void
    {
        $logger = new RecordingLogger();

        $this->deleteSubtreeWith(
            $this->handlerWith(
                3,
                eventLogger: new EventLogger(
                    $logger,
                    EventLogPolicy::default(),
                ),
            ),
            $this->context(),
        );

        self::assertSame(
            [
                EventContext::TARGET => [EventContext::DN => 'ou=people,dc=example,dc=com'],
                EventContext::ENTRIES_DELETED => 3,
                EventContext::COMPLETE => true,
                EventContext::EVENT => ServerEvent::SubtreeDeleted->value,
            ],
            $this->recordedWithoutDuration($logger),
        );
    }

    public function test_a_delete_stopped_by_the_limit_is_recorded_as_incomplete(): void
    {
        $logger = new RecordingLogger();

        try {
            $this->deleteSubtreeWith(
                $this->handlerWith(
                    2,
                    eventLogger: new EventLogger(
                        $logger,
                        EventLogPolicy::default(),
                    ),
                ),
                $this->context(),
            );
        } catch (OperationException) {
        }

        self::assertSame(
            [
                EventContext::TARGET => [EventContext::DN => 'ou=people,dc=example,dc=com'],
                EventContext::ENTRIES_DELETED => 2,
                EventContext::COMPLETE => false,
                EventContext::EVENT => ServerEvent::SubtreeDeleted->value,
            ],
            $this->recordedWithoutDuration($logger),
        );
    }

    public function test_a_delete_that_removed_nothing_is_not_recorded(): void
    {
        $logger = new RecordingLogger();

        try {
            $this->deleteSubtreeWith(
                $this->handlerWith(
                    3,
                    eventLogger: new EventLogger(
                        $logger,
                        EventLogPolicy::default(),
                    ),
                ),
                $this->controlledContext(Controls::assertion(Filters::equal('ou', 'nomatch'))),
            );
        } catch (OperationException) {
        }

        self::assertSame(
            [],
            $logger->records,
        );
    }

    public function test_an_assertion_the_base_fails_removes_nothing(): void
    {
        try {
            $this->graph->get(DeleteSubtreeHandler::class)->handle(
                new DeleteSubtreeCommand(new Dn('ou=people,dc=example,dc=com')),
                $this->controlledContext(Controls::assertion(Filters::equal('ou', 'nomatch'))),
            );
            self::fail('The assertion should have refused the delete.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ASSERTION_FAILED,
                $e->getCode(),
            );
            self::assertNull($this->deletedIn($e->controls()));
        }

        self::assertNotNull($this->find('ou=people,dc=example,dc=com'));
        self::assertNotNull($this->find('cn=alice,ou=people,dc=example,dc=com'));
    }

    public function test_a_pre_read_keeps_the_base_as_it_was(): void
    {
        $context = $this->controlledContext(Controls::preRead('ou'));

        $this->graph->get(DeleteSubtreeHandler::class)->handle(
            new DeleteSubtreeCommand(new Dn('ou=people,dc=example,dc=com')),
            $context,
        );

        self::assertNull($this->find('ou=people,dc=example,dc=com'));
        self::assertSame(
            'ou=people,dc=example,dc=com',
            $context->controlEvaluator()?->preReadEntry()?->getDn()->toString(),
        );
    }

    public function test_a_naming_context_base_is_refused_before_its_assertion(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->graph->get(DeleteSubtreeHandler::class)->handle(
            new DeleteSubtreeCommand(new Dn('dc=example,dc=com')),
            $this->controlledContext(Controls::assertion(Filters::equal('dc', 'nomatch'))),
        );
    }

    /**
     * Validation is opted into by the tests that assert on it, rather than applied to every fixture here.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
    }

    private function deleteSubtree(string $dn): void
    {
        $this->graph->get(DeleteSubtreeHandler::class)->handle(
            new DeleteSubtreeCommand(new Dn($dn)),
            $this->context(),
        );
    }

    private function deleteSubtreeWith(
        DeleteSubtreeHandler $handler,
        WriteContext $context,
    ): void {
        $handler->handle(
            new DeleteSubtreeCommand(new Dn('ou=people,dc=example,dc=com')),
            $context,
        );
    }

    private function handlerWith(
        int $maxEntries,
        ?SubtreeEnumerator $subtree = null,
        EventLogger $eventLogger = new EventLogger(null),
        SleeperInterface $sleeper = new BlockingSleeper(),
    ): DeleteSubtreeHandler {
        return new DeleteSubtreeHandler(
            $this->graph->get(EntryPlacementGuard::class),
            new SubtreeChunkRemover(
                $this->graph->get(LockedEntryAccess::class),
                $subtree ?? $this->graph->get(SubtreeEnumerator::class),
                $this->graph->get(WriteEntryInterface::class),
            ),
            eventLogger: $eventLogger,
            sleeper: $sleeper,
            maxEntries: $maxEntries,
        );
    }

    private function deletedIn(ControlBag $controls): ?int
    {
        $progress = $controls->get(Control::OID_SUBTREE_DELETE_PROGRESS);

        return $progress instanceof SubtreeDeleteProgressControl
            ? $progress->getDeleted()
            : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function recordedWithoutDuration(RecordingLogger $logger): array
    {
        self::assertCount(
            1,
            $logger->records,
        );
        $context = $logger->records[0]['context'];
        self::assertIsFloat($context[EventContext::DURATION_SECONDS] ?? null);
        unset($context[EventContext::DURATION_SECONDS]);

        return $context;
    }

    private function assertNoOrphans(): void
    {
        $entries = $this->storage->list(StorageListOptions::matchAll(
            new Dn('dc=example,dc=com'),
            subtree: true,
        ))->entries();

        foreach ($entries as $entry) {
            $parent = $entry->getDn()->getParent();
            if ($parent === null || $entry->getDn()->normalizedString() === 'dc=example,dc=com') {
                continue;
            }

            self::assertNotNull(
                $this->storage->find($parent->normalize()),
                $entry->getDn()->toString(),
            );
        }
    }

    /**
     * The journal refuses the base, so everything before the transaction holding it commits and that transaction does not.
     */
    private function graphWithFailingJournal(int $childCount): void
    {
        $kept = new InMemoryChangeJournal();
        $journal = $this->createMock(ChangeJournalInterface::class);
        $journal
            ->method('appendAll')
            ->willReturnCallback(static function (array $changes) use ($kept): array {
                /** @var list<PendingChange> $changes */
                foreach ($changes as $change) {
                    if ($change->dn->normalizedString() === 'ou=people,dc=example,dc=com') {
                        throw new StorageIoException('The journal is unavailable.');
                    }
                }

                return $kept->appendAll($changes);
            });
        $this->writeGraph(
            $this->peopleWithChildren($childCount),
            TestServerOptions::unvalidatedCore()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
            [ChangeJournalInterface::class => $journal],
        );
    }

    private function peopleWithChildren(int $childCount): InMemoryStorage
    {
        return EntryFixture::inMemoryStorage(...[
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            new Entry(new Dn('ou=people,dc=example,dc=com'), new Attribute('ou', 'people')),
            ...array_map(
                static fn(int $i): Entry => new Entry(
                    new Dn("cn=child{$i},ou=people,dc=example,dc=com"),
                    new Attribute('cn', "child{$i}"),
                ),
                range(
                    1,
                    $childCount,
                ),
            ),
        ]);
    }

    private function subtreeGraph(?InMemoryStorage $storage = null): void
    {
        $this->writeGraph($storage ?? EntryFixture::inMemoryStorage(
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            new Entry(new Dn('ou=people,dc=example,dc=com'), new Attribute('ou', 'people')),
            new Entry(new Dn('cn=alice,ou=people,dc=example,dc=com'), new Attribute('cn', 'alice')),
            new Entry(new Dn('cn=bob,ou=people,dc=example,dc=com'), new Attribute('cn', 'bob')),
        ));
    }

    private function journaledGraph(): InMemoryChangeJournal
    {
        $journal = new InMemoryChangeJournal();

        // Seeded directly so only the operations under test are journaled.
        $this->writeGraph(
            EntryFixture::inMemoryStorage(new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))),
            TestServerOptions::unvalidatedCore()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
            [ChangeJournalInterface::class => $journal],
        );

        return $journal;
    }

    private function seed(string $dn): void
    {
        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn($dn),
                new Attribute('objectClass', 'person'),
                new Attribute('cn', 'seed'),
            )),
            $this->context(),
        );
    }
}
