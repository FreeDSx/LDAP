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
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolationDisposition;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Write\WriteHandlerTestTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class AddEntryHandlerTest extends TestCase
{
    use WriteHandlerTestTrait;

    protected function setUp(): void
    {
        $this->writeGraph();
    }

    public function test_it_stores_the_entry(): void
    {
        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=New,dc=example,dc=com'),
                new Attribute('cn', 'New'),
            )),
            $this->context(),
        );

        self::assertNotNull($this->find('cn=New,dc=example,dc=com'));
    }

    public function test_it_refuses_an_entry_that_already_exists(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->adds()->handle(
            new AddCommand($this->alice),
            $this->context(),
        );
    }

    public function test_it_refuses_an_entry_whose_parent_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=New,ou=Missing,dc=example,dc=com'),
                new Attribute('cn', 'New'),
            )),
            $this->context(),
        );
    }

    public function test_a_missing_parent_carries_the_deepest_ancestor_as_the_matched_dn(): void
    {
        try {
            $this->adds()->handle(
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

    public function test_a_system_write_may_create_a_naming_context_root(): void
    {
        $this->writeGraph(new InMemoryStorage());

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('dc', 'example'),
            )),
            $this->systemContext(),
        );

        self::assertNotNull($this->find('dc=example,dc=com'));
    }

    public function test_a_system_write_may_not_create_an_entry_under_a_missing_parent(): void
    {
        $this->writeGraph(new InMemoryStorage());

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('dc', 'example'),
            )),
            $this->systemContext(),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=orphan,ou=absent,dc=example,dc=com'),
                new Attribute('cn', 'orphan'),
            )),
            $this->systemContext(),
        );
    }

    public function test_a_client_write_may_not_create_a_naming_context_root(): void
    {
        $this->writeGraph(new InMemoryStorage());

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('dc', 'example'),
            )),
            $this->context(),
        );
    }

    public function test_a_client_write_may_not_create_a_single_rdn_root(): void
    {
        $this->writeGraph(new InMemoryStorage());

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('dc=com'),
                new Attribute('dc', 'com'),
            )),
            $this->context(),
        );
    }

    public function test_it_stamps_the_operational_attributes(): void
    {
        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=New,dc=example,dc=com'),
                new Attribute('cn', 'New'),
            )),
            $this->context(),
        );

        $stored = $this->find('cn=New,dc=example,dc=com');
        self::assertNotNull($stored);
        self::assertNotNull($stored->get('createTimestamp'));
        self::assertNotNull($stored->get('modifyTimestamp'));
        self::assertNotNull($stored->get('creatorsName'));
        self::assertNotNull($stored->get('modifiersName'));
        self::assertNotNull($stored->get('entryUUID'));
    }

    public function test_a_storage_failure_propagates_carrying_its_result_code(): void
    {
        $ioException = new StorageIoException('Unable to publish the storage update.');
        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('atomic')
            ->willThrowException($ioException);
        $this->writeGraph($storage);

        try {
            $this->adds()->handle(
                new AddCommand(new Entry(
                    new Dn('cn=New,dc=example,dc=com'),
                    new Attribute('cn', 'New'),
                )),
                $this->context(),
            );
            self::fail('Expected StorageIoException was not thrown.');
        } catch (StorageIoException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
            self::assertSame(
                'The backend storage is currently unavailable.',
                $e->getDiagnostic(),
            );
        }
    }

    public function test_a_strict_validator_rejects_an_invalid_entry(): void
    {
        $this->validatedGraph(SchemaValidationMode::Strict);

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::OBJECT_CLASS_VIOLATION);

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=Invalid,dc=example,dc=com'),
                new Attribute('cn', 'Invalid'),
            )),
            $this->context(),
        );
    }

    public function test_a_strict_validator_accepts_a_valid_entry(): void
    {
        $this->validatedGraph(SchemaValidationMode::Strict);

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=Alice,dc=example,dc=com'),
                new Attribute('objectClass', 'top', 'person'),
                new Attribute('cn', 'Alice'),
                new Attribute('sn', 'Smith'),
            )),
            $this->context(),
        );

        self::assertNotNull($this->find('cn=Alice,dc=example,dc=com'));
    }

    public function test_a_lenient_validator_records_the_violation_and_writes_anyway(): void
    {
        $this->validatedGraph(SchemaValidationMode::Lenient);
        $violations = new SchemaViolations();

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=Invalid,dc=example,dc=com'),
                new Attribute('cn', 'Invalid'),
            )),
            $this->violationContext($violations),
        );

        self::assertNotNull($this->find('cn=Invalid,dc=example,dc=com'));
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

    public function test_the_relax_control_writes_anyway_under_a_strict_validator(): void
    {
        $this->validatedGraph(SchemaValidationMode::Strict);
        $violations = new SchemaViolations();

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=Invalid,dc=example,dc=com'),
                new Attribute('cn', 'Invalid'),
            )),
            $this->violationContext($violations, Controls::relaxRules()),
        );

        self::assertNotNull($this->find('cn=Invalid,dc=example,dc=com'));
        self::assertSame(
            SchemaViolationDisposition::RelaxedByControl,
            $violations->all()[0]->disposition,
        );
    }

    public function test_the_relax_control_does_not_excuse_invalid_attribute_syntax(): void
    {
        $this->validatedGraph(SchemaValidationMode::Strict);
        $violations = new SchemaViolations();

        $code = null;
        try {
            $this->adds()->handle(
                new AddCommand($this->badSyntaxEntry()),
                $this->violationContext($violations, Controls::relaxRules()),
            );
        } catch (OperationException $e) {
            $code = $e->getCode();
        }

        self::assertSame(
            ResultCode::INVALID_ATTRIBUTE_SYNTAX,
            $code,
        );
        self::assertNull($this->find('cn=Alice,dc=example,dc=com'));
        self::assertSame(
            SchemaViolationDisposition::Rejected,
            $violations->all()[0]->disposition,
        );
    }

    public function test_a_lenient_validator_does_not_excuse_invalid_attribute_syntax(): void
    {
        $this->validatedGraph(SchemaValidationMode::Lenient);
        $violations = new SchemaViolations();

        $code = null;
        try {
            $this->adds()->handle(
                new AddCommand($this->badSyntaxEntry()),
                $this->violationContext($violations),
            );
        } catch (OperationException $e) {
            $code = $e->getCode();
        }

        self::assertSame(
            ResultCode::INVALID_ATTRIBUTE_SYNTAX,
            $code,
        );
        self::assertNull($this->find('cn=Alice,dc=example,dc=com'));
        self::assertSame(
            SchemaViolationDisposition::Rejected,
            $violations->all()[0]->disposition,
        );
    }

    public function test_it_is_journaled_when_a_recorder_is_configured(): void
    {
        $journal = $this->journaledGraph();

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=New,dc=example,dc=com'),
                new Attribute('cn', 'New'),
            )),
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

    public function test_nothing_is_journaled_without_a_recorder(): void
    {
        $journal = new InMemoryChangeJournal();
        $this->writeGraph(new InMemoryStorage(
            [new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))],
            $journal,
        ));

        $this->adds()->handle(
            new AddCommand(new Entry(
                new Dn('cn=New,dc=example,dc=com'),
                new Attribute('cn', 'New'),
            )),
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

    private function validatedGraph(SchemaValidationMode $mode): void
    {
        $this->writeGraph(
            new InMemoryStorage([$this->base]),
            TestServerOptions::validatedCore($mode),
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

    private function badSyntaxEntry(): Entry
    {
        return new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'top', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('sn', 'Smith'),
            new Attribute('seeAlso', 'not a dn'),
        );
    }

    private function violationContext(
        SchemaViolations $violations,
        Control ...$controls,
    ): WriteContext {
        return new WriteContext(
            new AnonToken(),
            new ControlBag(...$controls),
            schemaViolations: $violations,
        );
    }
}
