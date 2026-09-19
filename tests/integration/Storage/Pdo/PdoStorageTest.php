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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Pdo;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use FreeDSx\Ldap\Server\Backend\StorageReadBackend;
use FreeDSx\Ldap\Server\Backend\Write\Operation\AddEntryHandler;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Pdo\EntryLinkFixtureTrait;
use Tests\Support\FreeDSx\Ldap\Journal\JournalingStorageContractTests;
use Tests\Support\FreeDSx\Ldap\Storage\SubtreeRenameStorageContractTests;

final class PdoStorageTest extends TestCase
{
    use ServerContainerTrait;

    use EntryLinkFixtureTrait;

    use JournalingStorageContractTests;

    use SubtreeRenameStorageContractTests;

    private StorageReadBackend $subject;

    private LdapImporter $importer;

    private PdoStorage $storage;

    private Entry $alice;

    protected function setUp(): void
    {
        $this->alice = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
            new Attribute('userPassword', 'secret'),
        );

        $this->storage = $this->pdoStorage(TestServerOptions::sqlite());
        $container = $this->containerFor($this->storage);
        $this->subject = $container->get(StorageReadBackend::class);
        $this->importer = $container->get(LdapImporter::class);
        $this->seed(
            new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
            $this->alice,
        );
    }

    /**
     * The SQL predicate has to answer the attribute's own EQUALITY rule, not a case-folded comparison.
     *
     * @param non-empty-string $attribute
     */
    #[DataProvider('rewrittenSpellingProvider')]
    public function test_a_value_matches_an_assertion_spelled_differently_under_its_matching_rule(
        string $attribute,
        string $stored,
        string $asserted,
    ): void {
        $this->storage->store(new Entry(
            new Dn('cn=spelling,dc=example,dc=com'),
            new Attribute('cn', 'spelling'),
            new Attribute($attribute, $stored),
        ));

        self::assertContains(
            'cn=spelling,dc=example,dc=com',
            $this->dnsMatching(Filters::equal($attribute, $asserted)),
        );
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function rewrittenSpellingProvider(): iterable
    {
        yield 'distinguishedNameMatch ignores RDN spacing and case' => [
            'member',
            'CN=Alice, DC=Example, DC=Com',
            'cn=alice,dc=example,dc=com',
        ];
        yield 'uniqueMemberMatch ignores RDN spacing and case' => [
            'uniqueMember',
            'CN=Alice, DC=Example, DC=Com',
            'cn=alice,dc=example,dc=com',
        ];
        yield 'telephoneNumberMatch ignores hyphens and spaces' => [
            'telephoneNumber',
            '+1-408-555-1212',
            '+1 408 555 1212',
        ];
        yield 'numericStringMatch ignores spaces' => [
            'x121Address',
            '1111 2222',
            '11112222',
        ];
    }

    /**
     * Its only stored attribute type lives in the password policy schema, so this one needs both sources merged.
     */
    public function test_a_generalized_time_value_matches_an_assertion_naming_the_same_instant(): void
    {
        // The policy schema is added for pwdChangedTime, whose syntax decides how the value is indexed.
        $options = TestServerOptions::sqlite();
        $options->getSchemaConfig()
            ->addSource(SchemaResource::PasswordPolicy);

        $storage = $this->pdoStorage($options);

        $storage->store(new Entry(
            new Dn('cn=stamped,dc=example,dc=com'),
            new Attribute('cn', 'stamped'),
            new Attribute('pwdChangedTime', '20260101070000-0500'),
        ));

        $entries = iterator_to_array($storage->list(new StorageListOptions(
            baseDn: new Dn('dc=example,dc=com'),
            subtree: true,
            filter: Filters::equal('pwdChangedTime', '20260101120000Z'),
        ))->entries());

        self::assertCount(1, $entries);
    }

    public function test_composed_and_streams_off_a_leaf_and_php_verifies_the_rest(): void
    {
        $this->seed(
            new Entry(
                new Dn('cn=bob,dc=example,dc=com'),
                new Attribute('cn', 'bob'),
                new Attribute('sn', 'common'),
                new Attribute('objectClass', 'person'),
            ),
            new Entry(
                new Dn('cn=carol,dc=example,dc=com'),
                new Attribute('cn', 'carol'),
                new Attribute('sn', 'common'),
                new Attribute('objectClass', 'device'),
            ),
        );

        // sn=common matches both; the AND drives off a leaf and PHP verifies the rest, so carol (objectClass=device) fails
        // the objectClass=person branch and is excluded.
        self::assertSame(
            ['cn=bob,dc=example,dc=com'],
            $this->searchDns(Filters::and(
                Filters::equal('sn', 'common'),
                Filters::equal('objectClass', 'person'),
            )),
        );
    }

    public function test_composed_and_with_no_matching_leaf_returns_nothing(): void
    {
        self::assertSame(
            [],
            $this->searchDns(Filters::and(
                Filters::equal('objectClass', 'person'),
                Filters::equal('cn', 'nobody'),
            )),
        );
    }

    public function test_infix_search_finds_matches_and_rejects_trigram_over_selection(): void
    {
        $this->seed(
            new Entry(
                new Dn('uid=match,dc=example,dc=com'),
                new Attribute('uid', 'match'),
                new Attribute('cn', 'blacksmith'),
            ),
            new Entry(
                new Dn('uid=scatter,dc=example,dc=com'),
                new Attribute('uid', 'scatter'),
                new Attribute('cn', 'smi mit ith'),
            ),
        );

        self::assertSame(
            ['uid=match,dc=example,dc=com'],
            $this->searchDns(Filters::contains('cn', 'smith')),
        );
    }

    public function test_a_linked_value_follows_the_target_through_a_rename(): void
    {
        $pdo = new PDO('sqlite::memory:');
        (new PdoSchema(new SqliteDialect()))->apply($pdo);
        $storage = $this->storageOver($pdo);
        $storage->store(new Entry(
            new Dn('cn=Bob,dc=example,dc=com'),
            new Attribute('cn', 'Bob'),
        ));
        $storage->store(new Entry(
            new Dn('cn=Admins,dc=example,dc=com'),
            new Attribute('cn', 'Admins'),
        ));
        $this->linkTogether(
            $pdo,
            'cn=admins,dc=example,dc=com',
            'cn=bob,dc=example,dc=com',
        );

        $storage->renameSubtree(
            new Dn('cn=bob,dc=example,dc=com'),
            new Dn('cn=Robert,dc=example,dc=com'),
        );

        self::assertSame(
            ['cn=Robert,dc=example,dc=com'],
            $storage->find(new Dn('cn=admins,dc=example,dc=com'))
                ?->get('member')
                ?->getValues(),
        );
    }

    public function test_deleting_the_target_removes_it_from_the_linked_attribute(): void
    {
        $pdo = new PDO('sqlite::memory:');
        (new PdoSchema(new SqliteDialect()))->apply($pdo);
        $storage = $this->storageOver($pdo);
        $storage->store(new Entry(
            new Dn('cn=Bob,dc=example,dc=com'),
            new Attribute('cn', 'Bob'),
        ));
        $storage->store(new Entry(
            new Dn('cn=Admins,dc=example,dc=com'),
            new Attribute('cn', 'Admins'),
        ));
        $this->linkTogether(
            $pdo,
            'cn=admins,dc=example,dc=com',
            'cn=bob,dc=example,dc=com',
        );

        $storage->remove(new Dn('cn=bob,dc=example,dc=com'));

        self::assertNull(
            $storage->find(new Dn('cn=admins,dc=example,dc=com'))
                ?->get('member'),
        );
    }

    public function test_list_single_level_returns_direct_children_only(): void
    {
        $grandchild = new Entry(new Dn('cn=Sub,cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $this->seed($grandchild);

        $request = (new SearchRequest(new AndFilter()))
            ->base('dc=example,dc=com')
            ->useSingleLevelScope();
        $results = iterator_to_array($this->subject->search(
            $request,
            SubentryVisibility::All,
        )->entries());

        self::assertCount(1, $results);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $results[0]->getDn()->toString(),
        );
    }

    public function test_list_recursive_includes_base_and_descendants(): void
    {
        $grandchild = new Entry(new Dn('cn=Sub,cn=Alice,dc=example,dc=com'), new Attribute('cn', 'Sub'));
        $this->seed($grandchild);

        $request = (new SearchRequest(new AndFilter()))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $results = iterator_to_array($this->subject->search(
            $request,
            SubentryVisibility::All,
        )->entries());

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

    public function test_option_bearing_equality_filter_matches_only_the_subtype(): void
    {
        $this->seed(
            new Entry(
                new Dn('uid=tagged,dc=example,dc=com'),
                new Attribute('uid', 'tagged'),
                new Attribute('cn;lang-en', 'shared'),
            ),
            new Entry(
                new Dn('uid=plain,dc=example,dc=com'),
                new Attribute('uid', 'plain'),
                new Attribute('cn', 'shared'),
            ),
        );

        self::assertSame(
            ['uid=tagged,dc=example,dc=com'],
            $this->searchDns(Filters::equal('cn;lang-en', 'shared')),
        );
        self::assertEqualsCanonicalizing(
            ['uid=tagged,dc=example,dc=com', 'uid=plain,dc=example,dc=com'],
            $this->searchDns(Filters::equal('cn', 'shared')),
        );
    }

    public function test_search_matches_mixed_case_attribute_via_lowercase_filter(): void
    {
        $request = (new SearchRequest(Filters::equal('userpassword', 'secret')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();

        $results = iterator_to_array($this->subject->search(
            $request,
            SubentryVisibility::All,
        )->entries());

        self::assertCount(1, $results);
        self::assertSame(
            'cn=Alice,dc=example,dc=com',
            $results[0]->getDn()->toString(),
        );
    }

    public function test_search_inexact_filter_trips_lookthrough_limit(): void
    {
        $backend = $this->seededBackend(
            TestServerOptions::unvalidatedCore()
                ->setMaxSearchLookthrough(2),
            ...$this->namedEntries(['Ann', 'Bob', 'Cyd']),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $request = (new SearchRequest(Filters::endsWith('cn', 'x')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        iterator_to_array($backend->search(
            $request,
            SubentryVisibility::All,
        )->entries());
    }

    public function test_search_exact_filter_within_the_lookthrough_limit_returns_every_match(): void
    {
        $backend = $this->seededBackend(
            TestServerOptions::unvalidatedCore()
                ->setMaxSearchLookthrough(5),
            ...$this->namedEntries(
                ['Ann', 'Bob', 'Cyd', 'Dan', 'Eve'],
                new Attribute('st', 'dup'),
            ),
        );

        $request = (new SearchRequest(Filters::equal('st', 'dup')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();

        self::assertCount(
            5,
            iterator_to_array($backend->search(
                $request,
                SubentryVisibility::All,
            )->entries()),
        );
    }

    public function test_search_exact_filter_trips_lookthrough_limit(): void
    {
        $backend = $this->seededBackend(
            TestServerOptions::unvalidatedCore()
                ->setMaxSearchLookthrough(2),
            ...$this->namedEntries(
                ['Ann', 'Bob', 'Cyd', 'Dan', 'Eve'],
                new Attribute('st', 'dup'),
            ),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $request = (new SearchRequest(Filters::equal('st', 'dup')))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        iterator_to_array($backend->search(
            $request,
            SubentryVisibility::All,
        )->entries());
    }

    public function test_atomic_rolls_back_on_exception(): void
    {
        $threw = false;

        try {
            $this->storage->atomic(function (): void {
                $this->storage->store(new Entry(
                    new Dn('cn=Rollback,dc=example,dc=com'),
                    new Attribute('cn', 'Rollback'),
                ));
                throw new \RuntimeException('intentional');
            });
        } catch (\RuntimeException) {
            $threw = true;
        }

        self::assertTrue($threw);
        self::assertNull($this->storage->find(new Dn('cn=rollback,dc=example,dc=com')));
    }

    public function test_atomic_commits_on_success(): void
    {
        $this->storage->atomic(function (): void {
            $this->storage->store(new Entry(
                new Dn('cn=Committed,dc=example,dc=com'),
                new Attribute('cn', 'Committed'),
            ));
        });

        self::assertNotNull($this->storage->find(new Dn('cn=committed,dc=example,dc=com')));
    }

    public function test_a_write_refuses_a_dn_longer_than_the_dialect_allows(): void
    {
        $container = $this->containerFor($this->createPdoStorageWithMaxDnLength(5));

        try {
            $container->get(AddEntryHandler::class)->handle(
                new AddCommand(new Entry(
                    new Dn('cn=TooLong,dc=example'),
                    new Attribute('cn', 'TooLong'),
                )),
                $this->systemContext(),
            );
            self::fail('Expected DnTooLongException was not thrown.');
        } catch (DnTooLongException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
        }
    }

    public function test_subtree_does_not_match_escaped_comma_suffix_collision(): void
    {
        $backend = $this->seededBackend(
            TestServerOptions::unvalidatedCore(),
            new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('dc', 'example'),
            ),
            new Entry(
                new Dn('cn=Doe\,John,dc=example,dc=com'),
                new Attribute('cn', 'Doe,John'),
            ),
        );

        $request = (new SearchRequest(new AndFilter()))
            ->base('John,dc=example,dc=com')
            ->useSubtreeScope();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        iterator_to_array($backend->search(
            $request,
            SubentryVisibility::All,
        )->entries());
    }

    public function test_subtree_includes_entries_with_escaped_comma_under_correct_parent(): void
    {
        $backend = $this->seededBackend(
            TestServerOptions::unvalidatedCore(),
            new Entry(
                new Dn('dc=example,dc=com'),
                new Attribute('dc', 'example'),
            ),
            new Entry(
                new Dn('cn=Doe\,John,dc=example,dc=com'),
                new Attribute('cn', 'Doe,John'),
            ),
        );

        $request = (new SearchRequest(new AndFilter()))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();
        $results = iterator_to_array($backend->search(
            $request,
            SubentryVisibility::All,
        )->entries());

        self::assertCount(2, $results);
    }

    public function test_nested_atomic_rolls_back_inner_on_exception(): void
    {
        $threw = false;

        $this->storage->atomic(function () use (&$threw): void {
            $this->storage->store(new Entry(
                new Dn('cn=Outer,dc=example,dc=com'),
                new Attribute('cn', 'Outer'),
            ));

            try {
                $this->storage->atomic(function (): void {
                    $this->storage->store(new Entry(
                        new Dn('cn=Inner,dc=example,dc=com'),
                        new Attribute('cn', 'Inner'),
                    ));
                    throw new \RuntimeException('inner fail');
                });
            } catch (\RuntimeException) {
                $threw = true;
            }
        });

        self::assertTrue($threw);
        self::assertNotNull($this->storage->find(new Dn('cn=outer,dc=example,dc=com')));
        self::assertNull($this->storage->find(new Dn('cn=inner,dc=example,dc=com')));
    }

    public function test_a_journal_append_rolls_back_with_the_enclosing_write_transaction(): void
    {
        $storage = $this->pdoStorage(
            TestServerOptions::sqlite()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );

        $journal = $storage->changeJournal() ?? self::fail('Expected the storage to have a journal.');

        try {
            $storage->atomic(function () use ($storage): void {
                $storage->appendChange(new PendingChange(
                    changeType: ChangeType::Add,
                    dn: new Dn('cn=a,dc=example,dc=com'),
                    entryUuid: '11111111-1111-4111-8111-111111111111',
                    authzId: AuthzId::anonymous(),
                ));

                throw new RuntimeException('force rollback');
            });
        } catch (RuntimeException) {
        }

        self::assertCount(
            0,
            iterator_to_array($journal->read()),
        );
        self::assertSame(
            0,
            $journal->latestSeq(),
        );
    }

    /**
     * The subject is the adapter rather than schema enforcement, so its fixtures are not held to one.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
    }

    protected function makeJournalingStorage(?ChangeJournalInterface $journal = null): ChangeJournalingInterface
    {
        if ($journal === null) {
            return $this->pdoStorage(TestServerOptions::sqlite());
        }

        return $this->fromContainer(
            PdoStorage::class,
            [ChangeJournalInterface::class => $journal],
            TestServerOptions::sqlite()
                ->setChangeJournalConfig(new ChangeJournalConfig()),
        );
    }

    protected function makeRenameStorage(Entry ...$entries): EntryStorageInterface
    {
        $storage = $this->pdoStorage(TestServerOptions::sqlite());

        foreach ($entries as $entry) {
            $storage->store($entry);
        }

        return $storage;
    }

    private function pdoStorage(ServerOptions $options): PdoStorage
    {
        return $this->fromContainer(
            PdoStorage::class,
            options: $options,
        );
    }

    /**
     * Storage the providers build over a connection the test owns, so it can seed or observe what the driver sees.
     *
     * @param ?PdoDialectInterface $dialect Pass one only to stub what the driver reports, such as its DN limit.
     */
    private function storageOver(
        PDO $pdo,
        ?PdoDialectInterface $dialect = null,
    ): PdoStorage {
        $overrides = [PdoConnectionProviderInterface::class => new SharedPdoConnectionProvider(
            $pdo,
            fn(): PDO => $pdo,
        )];

        if ($dialect !== null) {
            $overrides[PdoDialectInterface::class] = $dialect;
        }

        return $this->fromContainer(
            PdoStorage::class,
            $overrides,
            TestServerOptions::sqlite(),
        );
    }

    /**
     * @return list<string>
     */
    private function dnsMatching(FilterInterface $filter): array
    {
        $entries = $this->storage->list(new StorageListOptions(
            baseDn: new Dn('dc=example,dc=com'),
            subtree: true,
            filter: $filter,
        ))->entries();

        $dns = [];
        foreach ($entries as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    /**
     * @return list<string>
     */
    private function searchDns(FilterInterface $filter): array
    {
        $request = (new SearchRequest($filter))
            ->base('dc=example,dc=com')
            ->useSubtreeScope();

        $dns = [];
        foreach ($this->subject->search($request, SubentryVisibility::All)->entries() as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    private function systemContext(): WriteContext
    {
        return WriteContext::system(
            new AnonToken(),
            new ControlBag(),
        );
    }

    /**
     * Bulk load, so the fixture carries its operational attributes without the write pipeline being involved.
     */
    private function seed(Entry ...$entries): void
    {
        $this->importer->importEntries($entries);
    }

    /**
     * A backend over a fresh store, seeded with the given entries, for tests needing options the shared fixture lacks.
     */
    private function seededBackend(
        ServerOptions $options,
        Entry ...$entries,
    ): StorageReadBackend {
        $container = $this->containerFor(
            $this->pdoStorage(TestServerOptions::sqlite()),
            $options,
        );
        $container->get(LdapImporter::class)->importEntries($entries);

        return $container->get(StorageReadBackend::class);
    }

    /**
     * @param list<string> $names
     *
     * @return list<Entry> a naming context and one entry per name beneath it
     */
    private function namedEntries(
        array $names,
        Attribute ...$shared,
    ): array {
        $entries = [new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example'))];
        foreach ($names as $cn) {
            $entries[] = new Entry(
                new Dn("cn={$cn},dc=example,dc=com"),
                new Attribute('cn', $cn),
                ...$shared,
            );
        }

        return $entries;
    }

    private function createPdoStorageWithMaxDnLength(int $max): PdoStorage
    {
        $pdo = new PDO('sqlite::memory:');

        $sqlite = new SqliteDialect();
        $dialect = $this->createMock(PdoDialectInterface::class);
        $dialect->method('schemaStatements')
            ->willReturn($sqlite->schemaStatements());
        $dialect->method('queryUpsert')
            ->willReturn($sqlite->queryUpsert());
        $dialect->method('queryExists')
            ->willReturn($sqlite->queryExists());
        $dialect->method('queryFetchEntry')
            ->willReturn($sqlite->queryFetchEntry());
        $dialect->method('queryFetchChildren')
            ->willReturn($sqlite->queryFetchChildren());
        $dialect->method('maxDnLength')
            ->willReturn($max);

        (new PdoSchema($dialect))->apply($pdo);

        return $this->storageOver(
            $pdo,
            $dialect,
        );
    }
}
