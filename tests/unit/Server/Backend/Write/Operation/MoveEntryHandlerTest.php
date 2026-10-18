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

use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Write\WriteHandlerTestTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;

final class MoveEntryHandlerTest extends TestCase
{
    use WriteHandlerTestTrait;

    private const ALICE = 'cn=Alice,dc=example,dc=com';

    protected function setUp(): void
    {
        $this->writeGraph();
    }

    public function test_it_renames_the_entry(): void
    {
        $this->rename(self::ALICE, 'cn=Alicia');

        self::assertNull($this->find(self::ALICE));
        self::assertNotNull($this->find('cn=Alicia,dc=example,dc=com'));
    }

    public function test_it_creates_the_new_rdn_attribute_when_the_entry_lacks_it(): void
    {
        $this->rename(
            self::ALICE,
            'uid=alice',
            deleteOldRdn: false,
        );

        $entry = $this->find('uid=alice,dc=example,dc=com');
        self::assertNotNull($entry);
        self::assertTrue($entry->get('uid')?->has('alice'));
    }

    public function test_it_relocates_to_a_new_parent(): void
    {
        $this->addPeopleOu();

        $this->moves()->handle(
            new MoveCommand(
                new Dn(self::ALICE),
                Rdn::create('cn=Alice'),
                false,
                new Dn('ou=People,dc=example,dc=com'),
            ),
            $this->context(),
        );

        self::assertNull($this->find(self::ALICE));
        self::assertNotNull($this->find('cn=Alice,ou=People,dc=example,dc=com'));
    }

    public function test_it_refuses_an_entry_that_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->rename('cn=Nobody,dc=example,dc=com', 'cn=Ghost');
    }

    #[DataProvider('validationModeProvider')]
    public function test_a_rename_naming_the_entry_by_an_entry_uuid_is_refused_in_every_validation_mode(
        SchemaValidationMode $mode,
    ): void {
        $this->writeGraph(
            EntryFixture::inMemoryStorage(...$this->fixture()),
            TestServerOptions::validatedCore($mode),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->rename(
            self::ALICE,
            'entryUUID=a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
            deleteOldRdn: false,
        );
    }

    /**
     * @return iterable<string, array{SchemaValidationMode}>
     */
    public static function validationModeProvider(): iterable
    {
        foreach (SchemaValidationMode::cases() as $mode) {
            yield $mode->name => [$mode];
        }
    }

    public function test_a_failing_assertion_refuses_the_rename_and_leaves_the_entry(): void
    {
        try {
            $this->moves()->handle(
                new MoveCommand(
                    new Dn(self::ALICE),
                    Rdn::create('cn=Alicia'),
                    true,
                    null,
                ),
                $this->controlledContext(Controls::assertion(Filters::equal('cn', 'Nobody'))),
            );
            self::fail('The assertion should have refused the rename.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ASSERTION_FAILED,
                $e->getCode(),
            );
        }

        self::assertNotNull($this->find(self::ALICE));
        self::assertNull($this->find('cn=Alicia,dc=example,dc=com'));
    }

    public function test_the_entries_around_the_rename_are_kept_for_the_read_controls(): void
    {
        $context = $this->controlledContext(
            new PreReadControl('cn'),
            new PostReadControl('cn'),
        );

        $this->moves()->handle(
            new MoveCommand(
                new Dn(self::ALICE),
                Rdn::create('cn=Alicia'),
                true,
                null,
            ),
            $context,
        );

        $kept = $context->controlEvaluator();
        self::assertNotNull($kept);
        self::assertSame(
            self::ALICE,
            $kept->preReadEntry()?->getDn()->toString(),
        );
        $postRead = $kept->postReadEntry();
        self::assertNotNull($postRead);
        self::assertSame(
            'cn=Alicia,dc=example,dc=com',
            $postRead->getDn()->toString(),
        );
        self::assertSame(
            ['Alicia'],
            $postRead->get('cn')?->getValues(),
        );
    }

    public function test_it_relocates_an_entry_that_has_children(): void
    {
        $this->addPeopleOu();

        $this->moves()->handle(
            $this->renamePeopleToStaff(),
            $this->context(),
        );

        self::assertNotNull($this->find('ou=staff,dc=example,dc=com'));
        self::assertNull($this->find('ou=people,dc=example,dc=com'));
    }

    public function test_it_takes_the_descendants_with_it(): void
    {
        $this->addPeopleOu();

        $this->moves()->handle(
            $this->renamePeopleToStaff(),
            $this->context(),
        );

        self::assertNotNull($this->find('cn=bob,ou=staff,dc=example,dc=com'));
        self::assertNull($this->find('cn=bob,ou=people,dc=example,dc=com'));
    }

    public function test_it_refuses_a_new_superior_that_is_an_alias(): void
    {
        $this->writeGraph(EntryFixture::inMemoryStorage(...[...$this->fixture(), $this->aliasToAlice()]));

        try {
            $this->moves()->handle(
                new MoveCommand(
                    new Dn('cn=Alice,dc=example,dc=com'),
                    Rdn::create('cn=Alice'),
                    true,
                    new Dn('cn=Ptr,dc=example,dc=com'),
                ),
                $this->context(),
            );
            self::fail('A move beneath an alias should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ALIAS_PROBLEM,
                $e->getCode(),
            );
        }

        self::assertNotNull($this->find('cn=Alice,dc=example,dc=com'));
    }

    public function test_it_refuses_relocating_an_entry_beneath_itself(): void
    {
        $this->addPeopleOu();

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->moves()->handle(
            new MoveCommand(
                new Dn('ou=People,dc=example,dc=com'),
                Rdn::create('ou=Staff'),
                true,
                new Dn('cn=Bob,ou=People,dc=example,dc=com'),
            ),
            $this->context(),
        );
    }

    public function test_it_refuses_a_target_that_already_holds_subordinates(): void
    {
        // Seeded straight into storage: no write reaches this state, since one cannot land under a missing parent.
        $this->writeGraph(EntryFixture::inMemoryStorage(
            new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('dc', 'example'),
                new Attribute('objectClass', 'dcObject'),
            ),
            new Entry(
                new Dn('cn=Orphan,ou=Staff,dc=example,dc=com'),
                new Attribute('cn', 'Orphan'),
            ),
        ));
        $this->addPeopleOu();

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->moves()->handle(
            $this->renamePeopleToStaff(),
            $this->context(),
        );
    }

    public function test_it_refuses_a_new_superior_that_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->moves()->handle(
            new MoveCommand(
                new Dn(self::ALICE),
                Rdn::create('cn=Alice'),
                false,
                new Dn('ou=Missing,dc=example,dc=com'),
            ),
            $this->context(),
        );
    }

    public function test_it_refuses_a_target_dn_that_already_exists(): void
    {
        $this->writeGraph(EntryFixture::inMemoryStorage(
            new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('dc', 'example'),
                new Attribute('objectClass', 'dcObject'),
            ),
            new Entry(
                new Dn(self::ALICE),
                new Attribute('objectClass', 'person'),
                new Attribute('cn', 'Alice'),
            ),
            new Entry(new Dn('cn=Alicia,dc=example,dc=com'), new Attribute('cn', 'Alicia')),
        ));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->rename(self::ALICE, 'cn=Alicia');
    }

    public function test_it_refreshes_the_modify_operational_attributes(): void
    {
        $this->rename(self::ALICE, 'cn=Alicia');

        $moved = $this->find('cn=Alicia,dc=example,dc=com');
        self::assertNotNull($moved);
        self::assertNotNull($moved->get('modifyTimestamp'));
        self::assertNotNull($moved->get('modifiersName'));
    }

    public function test_a_storage_failure_propagates_carrying_its_result_code(): void
    {
        $transaction = $this->createMock(TransactionalWriteInterface::class);
        $transaction->method('atomic')
            ->willThrowException(new StorageIoException('Unable to publish the storage update.'));
        $this->writeGraph(sharedInstances: [TransactionalWriteInterface::class => $transaction]);

        self::expectException(StorageIoException::class);
        self::expectExceptionCode(ResultCode::UNAVAILABLE);

        $this->rename(self::ALICE, 'cn=Alicia');
    }

    public function test_it_is_journaled_with_the_previous_dn(): void
    {
        $journal = $this->journaledGraph();
        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=New,dc=example,dc=com'),
                new Attribute('objectClass', 'person'),
                new Attribute('cn', 'seed'),
            )),
            $this->context(),
        );

        $this->rename('cn=New,dc=example,dc=com', 'cn=Renamed');

        $records = iterator_to_array($journal->read());
        $last = end($records);
        self::assertInstanceOf(
            ChangeRecord::class,
            $last,
        );
        self::assertSame(
            ChangeType::ModRdn,
            $last->change->changeType,
        );
        self::assertSame(
            'cn=New,dc=example,dc=com',
            $last->change->previousDn?->toString(),
        );
    }

    public function test_a_renamed_container_journals_each_descendant_after_it_with_its_previous_dn(): void
    {
        $journal = $this->journaledGraph();
        foreach (['ou=Old,dc=example,dc=com', 'cn=Kid,ou=Old,dc=example,dc=com'] as $dn) {
            $this->adds()->handle(
                new AddCommand(new Entry(
                    new Dn($dn),
                    new Attribute('objectClass', 'person'),
                    new Attribute('cn', 'seed'),
                )),
                $this->context(),
            );
        }

        $this->rename('ou=Old,dc=example,dc=com', 'ou=New');

        self::assertSame(
            [
                'ou=New,dc=example,dc=com' => 'ou=Old,dc=example,dc=com',
                'cn=Kid,ou=New,dc=example,dc=com' => 'cn=kid,ou=old,dc=example,dc=com',
            ],
            $this->previousDnsJournaled($journal),
        );
    }

    /**
     * Validation is opted into by the tests that assert on it, rather than applied to every fixture here.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
    }

    private function rename(
        string $dn,
        string $newRdn,
        bool $deleteOldRdn = true,
    ): void {
        $this->moves()->handle(
            new MoveCommand(
                new Dn($dn),
                Rdn::create($newRdn),
                $deleteOldRdn,
                null,
            ),
            $this->context(),
        );
    }

    /**
     * The shared fixture puts cn=Bob under this, but leaves the OU itself out.
     */
    private function addPeopleOu(): void
    {
        $this->adds()->handle(
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

    private function journaledGraph(): InMemoryChangeJournal
    {
        $journal = new InMemoryChangeJournal();

        // Seeded directly so only the operation under test is journaled.
        $this->writeGraph(
            EntryFixture::inMemoryStorage(new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))),
            TestServerOptions::unvalidatedCore()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
            [ChangeJournalInterface::class => $journal],
        );

        return $journal;
    }

    /**
     * @return array<string, ?string> the previous DN of each ModRdn record, keyed by the DN it moved to
     */
    private function previousDnsJournaled(InMemoryChangeJournal $journal): array
    {
        $previousDns = [];

        foreach ($journal->read() as $record) {
            if ($record->change->changeType !== ChangeType::ModRdn) {
                continue;
            }

            $previousDns[$record->change->dn->toString()] = $record->change->previousDn?->toString();
        }

        return $previousDns;
    }
}
