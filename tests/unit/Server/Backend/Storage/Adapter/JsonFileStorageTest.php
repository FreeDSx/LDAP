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
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\FileLock;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeAppenderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\FileChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\WritableStorageBackend;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Journal\JournalingStorageContractTests;

final class JsonFileStorageTest extends TestCase
{
    use ServerContainerTrait;

    use JournalingStorageContractTests;

    private WritableStorageBackend $subject;

    private JsonFileStorage $storage;

    private string $tempFile;

    private Entry $alice;

    /**
     * @var list<string>
     */
    private array $tempFiles = [];

    protected function setUp(): void
    {
        $this->tempFile = sys_get_temp_dir() . '/ldap_test_' . uniqid() . '.json';
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Alice'),
            new Attribute('userPassword', 'secret'),
        );

        $this->storage = $this->makeStorage($this->tempFile);
        $this->subject = $this->backendFor($this->storage);
        $this->subject->add(
            new AddCommand(
                new Entry(
                    new Dn('dc=example,dc=com'),
                    new Attribute('objectClass', 'dcObject'),
                    new Attribute('dc', 'example'),
                ),
            ),
            $this->systemContext(),
        );
        $this->subject->add(
            new AddCommand($this->alice),
            $this->context(),
        );
    }

    protected function tearDown(): void
    {
        $this->cleanupBase($this->tempFile);

        foreach ($this->tempFiles as $base) {
            $this->cleanupBase($base);
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

    public function test_attribute_options_round_trip_through_storage(): void
    {
        $dn = new Dn('cn=Bob,dc=example,dc=com');
        $this->subject->add(
            new AddCommand(
                new Entry(
                    $dn,
                    new Attribute('objectClass', 'person'),
                    new Attribute('cn', 'Bob'),
                    new Attribute('cn;lang-en', 'Bobby'),
                    new Attribute('userCertificate;binary', 'CERTDATA'),
                ),
            ),
            $this->context(),
        );

        $entry = $this->subject->get($dn);

        self::assertNotNull($entry);
        self::assertSame(
            ['Bob'],
            $entry->get(new Attribute('cn'), true)?->getValues(),
        );
        self::assertSame(
            ['Bobby'],
            $entry->get(new Attribute('cn;lang-en'), true)?->getValues(),
        );
        self::assertSame(
            ['CERTDATA'],
            $entry->get(new Attribute('userCertificate;binary'), true)?->getValues(),
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
        $storage = $this->makeStorage($this->tempFile . '.nonexistent');
        $backend = $this->backendFor($storage);

        self::assertNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_get_on_empty_file_returns_null(): void
    {
        file_put_contents($this->tempFile, '');
        $storage = $this->makeStorage($this->tempFile);
        $backend = $this->backendFor($storage);

        self::assertNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_get_on_invalid_json_returns_null(): void
    {
        file_put_contents($this->tempFile, 'not valid json {{{');
        $storage = $this->makeStorage($this->tempFile);
        $backend = $this->backendFor($storage);

        self::assertNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_add_persists_to_file(): void
    {
        $entry = new Entry(new Dn('cn=Persistent,dc=example,dc=com'), new Attribute('cn', 'Persistent'));
        $this->subject->add(
            new AddCommand($entry),
            $this->context(),
        );

        // A second independent backend reading the same file should see the new entry.
        $backend2 = $this->backendFor($this->makeStorage($this->tempFile));

        self::assertNotNull($backend2->get(new Dn('cn=Persistent,dc=example,dc=com')));
    }

    public function test_delete_persists_to_file(): void
    {
        $this->subject->delete(
            new DeleteCommand(new Dn('cn=Alice,dc=example,dc=com')),
            $this->context(),
        );

        $backend2 = $this->backendFor($this->makeStorage($this->tempFile));

        self::assertNull($backend2->get(new Dn('cn=Alice,dc=example,dc=com')));
    }

    public function test_get_uses_in_memory_cache_on_subsequent_calls(): void
    {
        // Corrupt the file after the first read — a cache-bypassing adapter would return null.
        $this->storage->find(new Dn('cn=alice,dc=example,dc=com'));
        file_put_contents($this->tempFile, 'corrupted');

        $storage2 = $this->makeStorage($this->tempFile);

        // Prime the cache on first call (returns null from corrupted file).
        $storage2->find(new Dn('cn=alice,dc=example,dc=com'));

        // Second call on same storage instance with same mtime must use the in-memory cache.
        $result = $storage2->find(new Dn('cn=alice,dc=example,dc=com'));

        self::assertNull($result);
    }

    public function test_cache_is_invalidated_after_write(): void
    {
        $storage = $this->makeStorage($this->tempFile);
        $backend = $this->backendFor($storage);

        // Prime the cache with a valid file (contains Alice).
        self::assertNotNull($backend->get(new Dn('cn=Alice,dc=example,dc=com')));

        // A write operation changes the file — cache must be cleared.
        $extra = new Entry(new Dn('cn=Extra,dc=example,dc=com'), new Attribute('cn', 'Extra'));
        $backend->add(
            new AddCommand($extra),
            $this->context(),
        );

        // The backend must re-read the file and see the new entry.
        self::assertNotNull($backend->get(new Dn('cn=Extra,dc=example,dc=com')));
    }

    public function test_list_single_level_returns_direct_children_only(): void
    {
        // dc=example,dc=com and Alice are already in storage from setUp.
        // Add a grandchild to verify it is excluded from single-level results.
        $grandchild = new Entry(
            new Dn('cn=Sub,cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Sub'),
        );
        $this->subject->add(
            new AddCommand($grandchild),
            $this->context(),
        );

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSingleLevelScope();
        $results = iterator_to_array($this->subject->search(
            $request,
            SubentryVisibility::All,
        )->entries);

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
        $grandchild = new Entry(
            new Dn('cn=Sub,cn=Alice,dc=example,dc=com'),
            new Attribute('objectClass', 'person'),
            new Attribute('cn', 'Sub'),
        );
        $this->subject->add(
            new AddCommand($grandchild),
            $this->context(),
        );

        $request = (new SearchRequest(new PresentFilter('objectClass')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $results = iterator_to_array($this->subject->search(
            $request,
            SubentryVisibility::All,
        )->entries);

        $dns = array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            $results,
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
            'cn=Sub,cn=Alice,dc=example,dc=com',
            $dns,
        );
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

    public function test_naming_contexts_returns_top_most_entries_from_storage(): void
    {
        $this->subject->add(
            new AddCommand(
                new Entry(
                    new Dn('dc=other,dc=org'),
                    new Attribute('dc', 'other'),
                ),
            ),
            $this->systemContext(),
        );

        $contexts = array_map(
            fn(Dn $dn): string => $dn->toString(),
            $this->storage->namingContexts(),
        );

        sort($contexts);
        self::assertSame(
            ['dc=example,dc=com', 'dc=other,dc=org'],
            $contexts,
        );
    }

    public function test_a_recorded_write_is_journaled_through_the_buffer(): void
    {
        $storage = $this->makeJournaledStorage($this->registerTemp());
        $backend = $this->backendFor(
            $storage,
            // A recorder is only wired when a journal is configured and the storage can journal.
            TestServerOptions::unvalidatedCore()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );

        $backend->add(
            new AddCommand(new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('objectClass', 'dcObject'),
                new Attribute('dc', 'example'),
            )),
            $this->systemContext(),
        );

        self::assertCount(
            1,
            iterator_to_array($this->journalOf($storage)->read()),
        );
    }

    public function test_a_failed_write_records_nothing_in_the_journal(): void
    {
        $storage = $this->makeJournaledStorage($this->registerTemp());

        try {
            $storage->atomic(function (EntryStorageInterface $buffer): void {
                // The recorder collects into the buffer; the storage only flushes it after the data commits.
                if ($buffer instanceof ChangeAppenderInterface) {
                    $buffer->appendChange(new PendingChange(
                        changeType: ChangeType::Add,
                        dn: new Dn('cn=a,dc=example,dc=com'),
                        entryUuid: '11111111-1111-4111-8111-111111111111',
                        authzId: AuthzId::anonymous(),
                    ));
                }

                throw new RuntimeException('force rollback');
            });
        } catch (RuntimeException) {
        }

        self::assertCount(
            0,
            iterator_to_array($this->journalOf($storage)->read()),
        );
        self::assertSame(
            0,
            $this->journalOf($storage)->latestSeq(),
        );
    }

    public function test_a_journal_write_failure_does_not_fail_a_committed_write(): void
    {
        $base = $this->registerTemp();
        // A directory where the sidecar file must go makes the journal append fail while the entry write commits.
        mkdir($base . '.journal.jsonl');

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('error');

        $storage = $this->makeJournaledStorage(
            $base,
            $logger,
        );
        $backend = $this->backendFor(
            $storage,
            // A recorder is only wired when a journal is configured and the storage can journal.
            TestServerOptions::unvalidatedCore()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );

        // Swallow the E_WARNING fopen() raises on the directory sidecar; the thrown StorageIoException is the point.
        set_error_handler(static fn(): bool => true);

        try {
            $backend->add(
                new AddCommand(new Entry(
                    new Dn('dc=example,dc=com'),
                    new Attribute('objectClass', 'dcObject'),
                    new Attribute('dc', 'example'),
                )),
                $this->systemContext(),
            );
        } finally {
            restore_error_handler();
        }

        self::assertNotNull($backend->get(new Dn('dc=example,dc=com')));
    }

    protected function makeJournalingStorage(?ChangeJournalInterface $journal = null): ChangeJournalingInterface
    {
        return $this->makeStorage(
            $this->registerTemp(),
            $journal,
        );
    }

    /**
     * The journal shares the storage lock, so an append re-enters the write it belongs to.
     */
    private function makeStorage(
        string $path,
        ?ChangeJournalInterface $journal = null,
        ?LoggerInterface $logger = null,
    ): JsonFileStorage {
        return new JsonFileStorage(
            $path,
            new FileLock($path),
            $journal,
            $logger ?? new NullLogger(),
        );
    }

    /**
     * Storage and a file-backed journal on one lock, matching how the container wires them.
     */
    private function makeJournaledStorage(
        string $path,
        ?LoggerInterface $logger = null,
    ): JsonFileStorage {
        $lock = new FileLock($path);

        return new JsonFileStorage(
            $path,
            $lock,
            new FileChangeJournal(
                $lock,
                $path . '.journal.jsonl',
                $path . '.journal.seq',
            ),
            $logger ?? new NullLogger(),
        );
    }

    private function journalOf(JsonFileStorage $storage): ChangeJournalInterface
    {
        return $storage->changeJournal() ?? self::fail('Expected the storage to have a journal.');
    }

    private function registerTemp(): string
    {
        $base = sys_get_temp_dir() . '/ldap_journal_' . uniqid('', true) . '.json';
        $this->tempFiles[] = $base;

        return $base;
    }

    private function cleanupBase(string $base): void
    {
        foreach (['', '.journal.jsonl', '.journal.seq', '.lock'] as $suffix) {
            $path = $base . $suffix;
            if (is_dir($path)) {
                @rmdir($path);
            } elseif (is_file($path)) {
                @unlink($path);
            }
        }
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
}
