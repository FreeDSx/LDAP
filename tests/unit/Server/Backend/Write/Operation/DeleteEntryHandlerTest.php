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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\InMemoryChangeJournal;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Write\WriteHandlerTestTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class DeleteEntryHandlerTest extends TestCase
{
    use WriteHandlerTestTrait;

    protected function setUp(): void
    {
        $this->writeGraph();
    }

    public function test_it_removes_the_entry(): void
    {
        $this->deletes()->handle(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
            $this->context(),
        );

        self::assertNull($this->find('cn=Alice,dc=example,dc=com'));
    }

    public function test_it_refuses_an_entry_that_does_not_exist(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->deletes()->handle(
            new DeleteCommand(new Dn('cn=Nobody,dc=example,dc=com')),
            $this->context(),
        );
    }

    public function test_a_missing_entry_carries_the_deepest_ancestor_as_the_matched_dn(): void
    {
        try {
            $this->deletes()->handle(
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

    public function test_it_refuses_an_entry_that_holds_subordinates(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NOT_ALLOWED_ON_NON_LEAF);

        $this->deletes()->handle(
            new DeleteCommand(new Dn('dc=example,dc=com')),
            $this->context(),
        );
    }

    public function test_it_refuses_a_naming_context(): void
    {
        $this->writeGraph(new InMemoryStorage([
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
        ]));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->deletes()->handle(
            new DeleteCommand(new Dn('dc=example,dc=com')),
            $this->context(),
        );
    }

    public function test_it_allows_an_entry_whose_parent_is_present(): void
    {
        $this->writeGraph(new InMemoryStorage([
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            new Entry(new Dn('cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Alice')),
        ]));

        $this->deletes()->handle(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
            $this->context(),
        );

        self::assertNull($this->find('cn=Alice,dc=example,dc=com'));
    }

    public function test_a_storage_failure_propagates_carrying_its_result_code(): void
    {
        /** @var EntryStorageInterface&MockObject $storage */
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('atomic')
            ->willThrowException(new StorageIoException('Unable to acquire exclusive lock on the storage backend.'));
        $this->writeGraph($storage);

        self::expectException(StorageIoException::class);
        self::expectExceptionCode(ResultCode::UNAVAILABLE);

        $this->deletes()->handle(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
            $this->context(),
        );
    }

    public function test_it_is_journaled_with_a_pre_image(): void
    {
        $journal = $this->journaledGraph();
        $this->seed('cn=New,dc=example,dc=com');

        $this->deletes()->handle(
            new DeleteCommand(new Dn('cn=New,dc=example,dc=com')),
            $this->context(),
        );

        $records = iterator_to_array($journal->read());
        $last = end($records);
        self::assertInstanceOf(
            ChangeRecord::class,
            $last,
        );
        self::assertSame(
            ChangeType::Delete,
            $last->change->changeType,
        );
        self::assertNotNull($last->change->preImage);
    }

    /**
     * Validation is opted into by the tests that assert on it, rather than applied to every fixture here.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
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
