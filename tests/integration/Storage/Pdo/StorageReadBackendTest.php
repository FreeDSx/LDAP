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

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use FreeDSx\Ldap\Server\Backend\StorageReadBackend;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class StorageReadBackendTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private StorageReadBackend $subject;

    private LdapImporter $importer;

    protected function setUp(): void
    {
        $container = Container::forServer(TestServerOptions::sqlite());
        $this->subject = $container->get(StorageReadBackend::class);
        $this->importer = $container->get(LdapImporter::class);

        $this->importer->importEntries([
            new Entry(
                new Dn(self::BASE),
                new Attribute('dc', 'example'),
            ),
            new Entry(
                new Dn('cn=Alice,dc=example,dc=com'),
                new Attribute('cn', 'Alice'),
                new Attribute('userPassword', 'secret'),
            ),
        ]);
    }

    public function test_a_composed_and_drives_off_a_leaf_and_the_rest_is_verified(): void
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

        // Both match sn=common, so only the re-check of the other branch can leave carol out.
        self::assertSame(
            ['cn=bob,dc=example,dc=com'],
            $this->searchDns(Filters::and(
                Filters::equal('sn', 'common'),
                Filters::equal('objectClass', 'person'),
            )),
        );
    }

    public function test_a_composed_and_with_no_matching_leaf_returns_nothing(): void
    {
        self::assertSame(
            [],
            $this->searchDns(Filters::and(
                Filters::equal('objectClass', 'person'),
                Filters::equal('cn', 'nobody'),
            )),
        );
    }

    public function test_an_infix_search_finds_matches_and_rejects_trigram_over_selection(): void
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

    public function test_a_single_level_search_returns_direct_children_only(): void
    {
        $this->seed(new Entry(
            new Dn('cn=Sub,cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Sub'),
        ));

        self::assertSame(
            ['cn=Alice,dc=example,dc=com'],
            $this->dns((new SearchRequest(new AndFilter()))
                ->base(self::BASE)
                ->useSingleLevelScope()),
        );
    }

    public function test_a_subtree_search_includes_the_base_and_every_descendant(): void
    {
        $this->seed(new Entry(
            new Dn('cn=Sub,cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Sub'),
        ));

        self::assertEqualsCanonicalizing(
            [
                'dc=example,dc=com',
                'cn=Alice,dc=example,dc=com',
                'cn=Sub,cn=Alice,dc=example,dc=com',
            ],
            $this->searchDns(new AndFilter()),
        );
    }

    public function test_an_option_bearing_equality_filter_matches_only_the_subtype(): void
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

    public function test_a_lowercase_filter_matches_a_mixed_case_attribute(): void
    {
        self::assertSame(
            ['cn=Alice,dc=example,dc=com'],
            $this->searchDns(Filters::equal('userpassword', 'secret')),
        );
    }

    public function test_an_inexact_filter_trips_the_lookthrough_limit(): void
    {
        $backend = $this->seededBackend(
            TestServerOptions::sqlite()->setMaxSearchLookthrough(2),
            ...$this->namedEntries(['Ann', 'Bob', 'Cyd']),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->dns(
            (new SearchRequest(Filters::endsWith('cn', 'x')))
                ->base(self::BASE)
                ->useSubtreeScope(),
            $backend,
        );
    }

    public function test_an_exact_filter_within_the_lookthrough_limit_returns_every_match(): void
    {
        $backend = $this->seededBackend(
            TestServerOptions::sqlite()->setMaxSearchLookthrough(5),
            ...$this->namedEntries(
                ['Ann', 'Bob', 'Cyd', 'Dan', 'Eve'],
                new Attribute('st', 'dup'),
            ),
        );

        self::assertCount(
            5,
            $this->dns(
                (new SearchRequest(Filters::equal('st', 'dup')))
                    ->base(self::BASE)
                    ->useSubtreeScope(),
                $backend,
            ),
        );
    }

    public function test_an_exact_filter_trips_the_lookthrough_limit(): void
    {
        $backend = $this->seededBackend(
            TestServerOptions::sqlite()->setMaxSearchLookthrough(2),
            ...$this->namedEntries(
                ['Ann', 'Bob', 'Cyd', 'Dan', 'Eve'],
                new Attribute('st', 'dup'),
            ),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->dns(
            (new SearchRequest(Filters::equal('st', 'dup')))
                ->base(self::BASE)
                ->useSubtreeScope(),
            $backend,
        );
    }

    public function test_a_subtree_base_does_not_match_a_suffix_collision_through_an_escaped_comma(): void
    {
        $this->seed(new Entry(
            new Dn('cn=Doe\,John,dc=example,dc=com'),
            new Attribute('cn', 'Doe,John'),
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->dns((new SearchRequest(new AndFilter()))
            ->base('John,dc=example,dc=com')
            ->useSubtreeScope());
    }

    public function test_a_subtree_search_includes_an_entry_with_an_escaped_comma_under_its_parent(): void
    {
        $this->seed(new Entry(
            new Dn('cn=Doe\,John,dc=example,dc=com'),
            new Attribute('cn', 'Doe,John'),
        ));

        self::assertContains(
            'cn=Doe\,John,dc=example,dc=com',
            $this->searchDns(new AndFilter()),
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
     * @return list<string>
     */
    private function searchDns(FilterInterface $filter): array
    {
        return $this->dns((new SearchRequest($filter))
            ->base(self::BASE)
            ->useSubtreeScope());
    }

    /**
     * @return list<string>
     */
    private function dns(
        SearchRequest $request,
        ?StorageReadBackend $backend = null,
    ): array {
        $dns = [];
        foreach (($backend ?? $this->subject)->search($request, SubentryVisibility::All)->entries() as $entry) {
            $dns[] = $entry->getDn()->toString();
        }

        return $dns;
    }

    /**
     * A backend over a fresh store, seeded with the given entries, for tests needing options the shared fixture lacks.
     */
    private function seededBackend(
        ServerOptions $options,
        Entry ...$entries,
    ): StorageReadBackend {
        $container = Container::forServer($options);
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
        $entries = [new Entry(new Dn(self::BASE), new Attribute('dc', 'example'))];
        foreach ($names as $cn) {
            $entries[] = new Entry(
                new Dn("cn={$cn},dc=example,dc=com"),
                new Attribute('cn', $cn),
                ...$shared,
            );
        }

        return $entries;
    }
}
