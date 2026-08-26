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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\FetchedBatch;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\StorageReadBackend;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use FreeDSx\Ldap\ServerOptions;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class StorageReadBackendTest extends TestCase
{
    use ServerContainerTrait;

    private StorageReadBackend $subject;

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
        $subject = $this->aliasBackend();

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
        $subject = $this->aliasBackend();

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
        $subject = $this->aliasBackend();

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
        $subject = $this->aliasBackend();

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

    public function test_no_such_object_with_no_existing_ancestor_has_null_matched_dn(): void
    {
        $backend = $this->backendFor(new InMemoryStorage());

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

    /**
     * Validation is opted into by the tests that assert on it, rather than applied to every fixture here.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
    }

    private function aliasBackend(): StorageReadBackend
    {
        return $this->backendFor(new InMemoryStorage([
            $this->base,
            $this->alice,
            new Entry(
                new Dn('cn=ref,dc=example,dc=com'),
                new Attribute('objectClass', 'alias'),
                new Attribute('aliasedObjectName', 'cn=Alice,dc=example,dc=com'),
            ),
        ]));
    }

    /**
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     */
    private function makeTimeLimitStream(): Generator
    {
        yield new Entry(new Dn('dc=example,dc=com'));

        throw new TimeLimitExceededException();
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
}
