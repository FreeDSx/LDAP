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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\ServerOptions;
use Generator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Write\WriteHandlerTestTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

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
        $this->writeGraph(new InMemoryStorage([
            new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('dc', 'example'),
                new Attribute('objectClass', 'dcObject'),
            ),
            new Entry(
                new Dn('cn=Orphan,ou=Staff,dc=example,dc=com'),
                new Attribute('cn', 'Orphan'),
            ),
        ]));
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
        $this->writeGraph(new InMemoryStorage([
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
        ]));

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
        $alice = new Entry(
            new Dn(self::ALICE),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Alice'),
        );

        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('find')
            ->willReturn($alice);
        $storage->method('exists')
            ->willReturn(true);
        $storage->method('list')
            ->willReturn(EntryStream::of($this->oneEntry($alice)));
        $storage->method('atomic')
            ->willThrowException(new StorageIoException('Unable to publish the storage update.'));
        $this->writeGraph($storage);

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
            new InMemoryStorage(
                [new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))],
                $journal,
            ),
            TestServerOptions::unvalidatedCore()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );

        return $journal;
    }

    /**
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     */
    private function oneEntry(Entry $entry): Generator
    {
        yield $entry;

        return null;
    }
}
