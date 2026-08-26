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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolationDisposition;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Write\WriteHandlerTestTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class UpdateEntryHandlerTest extends TestCase
{
    use WriteHandlerTestTrait;

    private const ALICE = 'cn=Alice,dc=example,dc=com';

    protected function setUp(): void
    {
        $this->writeGraph();
    }

    public function test_it_adds_an_attribute_value(): void
    {
        $this->modify(new Change(Change::TYPE_ADD, 'mail', 'alice@example.com'));

        $entry = $this->find(self::ALICE);
        self::assertNotNull($entry);
        self::assertTrue($entry->get('mail')?->has('alice@example.com'));
    }

    public function test_it_adds_a_value_to_an_existing_attribute(): void
    {
        $this->modify(new Change(Change::TYPE_ADD, 'cn', 'Alicia'));

        $cn = $this->find(self::ALICE)?->get('cn');
        self::assertNotNull($cn);
        self::assertTrue($cn->has('Alice'));
        self::assertTrue($cn->has('Alicia'));
    }

    public function test_it_replaces_an_attribute_value(): void
    {
        $this->modify(new Change(Change::TYPE_REPLACE, 'userPassword', 'newpassword'));

        self::assertSame(
            ['newpassword'],
            $this->find(self::ALICE)?->get('userPassword')?->getValues(),
        );
    }

    public function test_it_deletes_an_attribute(): void
    {
        $this->modify(new Change(Change::TYPE_DELETE, 'userPassword'));

        self::assertNull($this->find(self::ALICE)?->get('userPassword'));
    }

    public function test_it_deletes_one_value_of_an_attribute(): void
    {
        $this->modify(new Change(Change::TYPE_DELETE, 'userPassword', 'secret'));

        self::assertFalse($this->find(self::ALICE)?->get('userPassword')?->has('secret') ?? false);
    }

    public function test_a_replace_with_no_values_clears_the_attribute(): void
    {
        $this->modify(new Change(Change::TYPE_REPLACE, 'userPassword'));

        self::assertNull($this->find(self::ALICE)?->get('userPassword'));
    }

    public function test_it_refuses_an_entry_that_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->updates()->handle(
            new UpdateCommand(
                new Dn('cn=Nobody,dc=example,dc=com'),
                [new Change(Change::TYPE_REPLACE, 'cn', 'Nobody')],
            ),
            $this->context(),
        );
    }

    public function test_a_missing_entry_carries_the_deepest_ancestor_as_the_matched_dn(): void
    {
        try {
            $this->updates()->handle(
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

    public function test_it_refreshes_the_modify_operational_attributes(): void
    {
        $this->modify(Change::replace(new Attribute('userPassword', 'newSecret')));

        $updated = $this->find(self::ALICE);
        self::assertNotNull($updated);
        self::assertNotNull($updated->get('modifyTimestamp'));
        self::assertNotNull($updated->get('modifiersName'));
    }

    public function test_a_storage_failure_is_answered_as_unavailable(): void
    {
        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('atomic')
            ->willThrowException(new StorageIoException('Unable to stage the storage update.'));
        $this->writeGraph($storage);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNAVAILABLE);
        self::expectExceptionMessage('The backend storage is currently unavailable.');

        $this->modify(new Change(Change::TYPE_REPLACE, 'cn', 'Alicia'));
    }

    public function test_a_strict_validator_rejects_an_invalid_modification(): void
    {
        $this->validatedGraph(SchemaValidationMode::Strict);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->modify(Change::replace(new Attribute('createTimestamp', '20240101000000Z')));
    }

    public function test_a_lenient_validator_records_the_violation_and_writes_anyway(): void
    {
        $this->validatedGraph(SchemaValidationMode::Lenient);
        $violations = new SchemaViolations();

        $this->updates()->handle(
            new UpdateCommand(
                new Dn(self::ALICE),
                [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
            ),
            new WriteContext(
                new AnonToken(),
                new ControlBag(),
                schemaViolations: $violations,
            ),
        );

        self::assertSame(
            '20240101000000Z',
            $this->find(self::ALICE)?->get('createTimestamp')?->firstValue(),
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

    public function test_a_system_write_bypasses_the_no_user_modification_check(): void
    {
        $this->validatedGraph(SchemaValidationMode::Strict);

        $this->updates()->handle(
            new UpdateCommand(
                new Dn(self::ALICE),
                [Change::replace(new Attribute('createTimestamp', '20240101000000Z'))],
            ),
            $this->systemContext(),
        );

        self::assertSame(
            '20240101000000Z',
            $this->find(self::ALICE)?->get('createTimestamp')?->firstValue(),
        );
    }

    public function test_a_system_write_still_enforces_a_single_valued_attribute(): void
    {
        $this->validatedGraph(SchemaValidationMode::Strict);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->updates()->handle(
            new UpdateCommand(
                new Dn(self::ALICE),
                [Change::replace(new Attribute('createTimestamp', '20240101000000Z', '20240202000000Z'))],
            ),
            $this->systemContext(),
        );
    }

    public function test_it_is_journaled(): void
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

        $this->updates()->handle(
            new UpdateCommand(
                new Dn('cn=New,dc=example,dc=com'),
                [new Change(Change::TYPE_ADD, 'mail', 'new@example.com')],
            ),
            $this->context(),
        );

        $records = iterator_to_array($journal->read());
        $last = end($records);
        self::assertInstanceOf(
            ChangeRecord::class,
            $last,
        );
        self::assertSame(
            ChangeType::Modify,
            $last->change->changeType,
        );
    }

    /**
     * Validation is opted into by the tests that assert on it, rather than applied to every fixture here.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
    }

    private function modify(Change ...$changes): void
    {
        $this->updates()->handle(
            new UpdateCommand(
                new Dn(self::ALICE),
                $changes,
            ),
            $this->context(),
        );
    }

    /**
     * A validated fixture needs an entry the core schema actually accepts.
     */
    private function validatedGraph(SchemaValidationMode $mode): void
    {
        $this->writeGraph(
            new InMemoryStorage([
                new Entry(
                    new Dn('dc=example,dc=com'),
                    new Attribute('dc', 'example'),
                    new Attribute('objectClass', 'dcObject'),
                ),
                new Entry(
                    new Dn(self::ALICE),
                    new Attribute('objectClass', 'top', 'person'),
                    new Attribute('cn', 'Alice'),
                    new Attribute('sn', 'Smith'),
                ),
            ]),
            TestServerOptions::validatedCore($mode),
        );
    }

    private function journaledGraph(): InMemoryChangeJournal
    {
        $journal = new InMemoryChangeJournal();

        // Seeded directly so only the operations under test are journaled.
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
}
