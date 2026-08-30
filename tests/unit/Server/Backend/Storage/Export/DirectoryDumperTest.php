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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Export;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Ldif\LdifOutputOptions;
use FreeDSx\Ldap\Ldif\LdifWriter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DirectoryDumper;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use Generator;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class DirectoryDumperTest extends TestCase
{
    use ServerContainerTrait;

    public function test_it_yields_the_version_header_first_when_enabled(): void
    {
        $dumper = $this->makeDumper();

        $chunks = iterator_to_array(
            $dumper->dump(new DumpOptions()),
            false,
        );

        self::assertSame(
            "version: 1\n\n",
            $chunks[0],
        );
    }

    public function test_it_omits_the_version_header_when_disabled(): void
    {
        $writer = new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false));
        $dumper = $this->makeDumper(writer: $writer);

        $chunks = iterator_to_array(
            $dumper->dump(new DumpOptions()),
            false,
        );

        self::assertStringStartsWith(
            'dn: ',
            $chunks[0],
        );
    }

    public function test_it_iterates_entries_across_naming_contexts_when_no_base_is_set(): void
    {
        $dumper = $this->makeDumper(
            writer: new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        $ldif = implode('', iterator_to_array(
            $dumper->dump(new DumpOptions()),
            false,
        ));

        self::assertStringContainsString(
            'dn: dc=foo,dc=bar',
            $ldif,
        );
        self::assertStringContainsString(
            'dn: cn=alice,dc=foo,dc=bar',
            $ldif,
        );
        self::assertStringContainsString(
            'dn: cn=bob,dc=foo,dc=bar',
            $ldif,
        );
    }

    public function test_it_separates_records_with_a_blank_line(): void
    {
        $dumper = $this->makeDumper(
            writer: new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        $ldif = implode('', iterator_to_array(
            $dumper->dump(new DumpOptions()),
            false,
        ));

        // RFC 2849 readers take a run of records with no blank line between them as one malformed record.
        $records = explode("\n\n", $ldif);

        self::assertCount(
            3,
            $records,
        );

        foreach ($records as $record) {
            self::assertStringStartsWith(
                'dn: ',
                $record,
            );
        }
    }

    public function test_it_restricts_to_the_options_base_dn_when_set(): void
    {
        $dumper = $this->makeDumper(
            writer: new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        $ldif = implode('', iterator_to_array(
            $dumper->dump((new DumpOptions())->setBaseDn(new Dn('cn=alice,dc=foo,dc=bar'))),
            false,
        ));

        self::assertStringContainsString(
            'dn: cn=alice,dc=foo,dc=bar',
            $ldif,
        );
        self::assertStringNotContainsString(
            'dn: cn=bob,dc=foo,dc=bar',
            $ldif,
        );
        self::assertStringNotContainsString(
            'dn: dc=foo,dc=bar',
            $ldif,
        );
    }

    public function test_it_re_evaluates_the_filter_when_the_stream_is_not_preFiltered(): void
    {
        $alice = Entry::create(
            'cn=alice,dc=foo,dc=bar',
            ['cn' => 'alice'],
        );
        $bob = Entry::create(
            'cn=bob,dc=foo,dc=bar',
            ['cn' => 'bob'],
        );
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('list')->willReturn(new EntryStream(
            entries: (function () use ($alice, $bob): Generator {
                yield $alice;
                yield $bob;

                return null;
            })(),
            isPreFiltered: false,
        ));
        $evaluator = $this->createMock(FilterEvaluatorInterface::class);
        $evaluator->method('evaluate')->willReturnCallback(
            fn(Entry $entry, FilterInterface $filter): bool
                => $entry->getDn()->toString() === 'cn=alice,dc=foo,dc=bar',
        );

        $dumper = $this->makeDumper(
            $storage,
            $evaluator,
            new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        $ldif = implode('', iterator_to_array(
            $dumper->dump((new DumpOptions())->setFilter(Filters::equal('cn', 'alice'))),
            false,
        ));

        self::assertStringContainsString(
            'cn=alice,dc=foo,dc=bar',
            $ldif,
        );
        self::assertStringNotContainsString(
            'cn=bob,dc=foo,dc=bar',
            $ldif,
        );
    }

    public function test_it_does_not_re_evaluate_the_filter_when_the_stream_is_preFiltered(): void
    {
        $alice = Entry::create('cn=alice,dc=foo,dc=bar', ['cn' => 'alice']);
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->method('list')->willReturn(new EntryStream(
            entries: (function () use ($alice): Generator {
                yield $alice;

                return null;
            })(),
            isPreFiltered: true,
        ));
        $evaluator = $this->createMock(FilterEvaluatorInterface::class);
        $evaluator->expects(self::never())->method('evaluate');

        $dumper = $this->makeDumper(
            $storage,
            $evaluator,
            new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        iterator_to_array(
            $dumper->dump((new DumpOptions())->setFilter(Filters::equal('cn', 'alice'))),
            false,
        );
    }

    public function test_it_passes_match_all_to_storage_when_no_filter_is_set(): void
    {
        $storage = $this->createMock(EntryStorageInterface::class);
        $storage->expects(self::once())
            ->method('list')
            ->with(self::callback(
                fn(StorageListOptions $opts): bool
                    => $opts->subtree === true && $opts->baseDn->toString() === 'dc=foo,dc=bar',
            ))
            ->willReturn(new EntryStream(
                entries: (function (): Generator {
                    yield from [];

                    return null;
                })(),
            ));

        $dumper = $this->makeDumper($storage);

        iterator_to_array(
            $dumper->dump(new DumpOptions()),
            false,
        );
    }

    /**
     * The subject, with only the collaborator a test cares about supplied.
     */
    private function makeDumper(
        ?EntryStorageInterface $storage = null,
        ?FilterEvaluatorInterface $filterEvaluator = null,
        ?LdifWriter $writer = null,
    ): DirectoryDumper {
        return new DirectoryDumper(
            $storage ?? $this->storageWithEntries(),
            [new Dn('dc=foo,dc=bar')],
            $filterEvaluator ?? $this->fromContainer(FilterEvaluatorInterface::class),
            $writer ?? new LdifWriter(),
        );
    }

    private function storageWithEntries(): InMemoryStorage
    {
        return new InMemoryStorage([
            new Entry(
                new Dn('dc=foo,dc=bar'),
                new Attribute('dc', 'foo'),
            ),
            new Entry(
                new Dn('cn=alice,dc=foo,dc=bar'),
                new Attribute('cn', 'alice'),
                new Attribute('sn', 'Anderson'),
            ),
            new Entry(
                new Dn('cn=bob,dc=foo,dc=bar'),
                new Attribute('cn', 'bob'),
                new Attribute('sn', 'Builder'),
            ),
        ]);
    }
}
