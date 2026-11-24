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
use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DirectoryDumper;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;

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

    #[DataProvider('otherSpellingProvider')]
    public function test_a_base_dn_naming_a_type_another_way_restricts_to_that_entry(string $base): void
    {
        $dumper = $this->makeDumper(
            writer: new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        $ldif = implode(
            '',
            iterator_to_array(
                $dumper->dump((new DumpOptions())->setBaseDn(new Dn($base))),
                false,
            ),
        );

        self::assertStringContainsString(
            'dn: cn=alice,dc=foo,dc=bar',
            $ldif,
        );
        self::assertStringNotContainsString(
            'dn: cn=bob,dc=foo,dc=bar',
            $ldif,
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function otherSpellingProvider(): iterable
    {
        yield 'an alias' => ['commonName=alice,dc=foo,dc=bar'];
        yield 'an OID' => ['2.5.4.3=alice,dc=foo,dc=bar'];
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

    public function test_a_filter_writes_only_the_entries_it_matches(): void
    {
        $dumper = $this->makeDumper(
            writer: new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        self::assertSame(
            ['cn=alice,dc=foo,dc=bar'],
            $this->dnsIn($dumper->dump((new DumpOptions())->setFilter(Filters::equal(
                'cn',
                'alice',
            )))),
        );
    }

    public function test_it_writes_a_parent_before_a_child_stored_ahead_of_it(): void
    {
        $dumper = $this->makeDumper(
            $this->storageWithAMovedEntry(),
            new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        self::assertSame(
            [
                'dc=foo,dc=bar',
                'ou=later,dc=foo,dc=bar',
                'cn=mover,ou=later,dc=foo,dc=bar',
            ],
            $this->dnsIn($dumper->dump(new DumpOptions())),
        );
    }

    public function test_a_filter_still_reaches_a_match_below_a_container_it_does_not_match(): void
    {
        $dumper = $this->makeDumper(
            $this->storageWithAMovedEntry(),
            new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        self::assertSame(
            ['cn=mover,ou=later,dc=foo,dc=bar'],
            $this->dnsIn($dumper->dump((new DumpOptions())->setFilter(Filters::equal(
                'cn',
                'mover',
            )))),
        );
    }

    public function test_a_filter_on_a_back_link_writes_the_entries_it_names(): void
    {
        $dumper = $this->makeDumper(
            $this->storageWithAGroup(),
            new LdifWriter((new LdifOutputOptions())->setIncludeVersion(false)),
        );

        self::assertSame(
            ['cn=alice,dc=foo,dc=bar'],
            $this->dnsIn($dumper->dump((new DumpOptions())->setFilter(Filters::equal(
                'memberOf',
                'cn=staff,dc=foo,dc=bar',
            )))),
        );
    }

    /**
     * The subject, with only the collaborator a test cares about supplied.
     */
    private function makeDumper(
        ?InMemoryStorage $storage = null,
        ?LdifWriter $writer = null,
    ): DirectoryDumper {
        $storage ??= $this->storageWithEntries();

        return new DirectoryDumper(
            new SubtreeEnumerator($storage),
            [new Dn('dc=foo,dc=bar')],
            $this->fromContainer(FilterEvaluatorInterface::class),
            $this->fromContainer(
                LinkedLeafWitness::class,
                [LinkedValueLookupInterface::class => $storage],
            ),
            $this->fromContainer(AttributeTypeSpelling::class),
            $writer ?? new LdifWriter(),
        );
    }

    /**
     * Holds the child ahead of the parent it was moved under, as storage order leaves a move.
     */
    private function storageWithAMovedEntry(): InMemoryStorage
    {
        return EntryFixture::inMemoryStorage(
            new Entry(
                new Dn('dc=foo,dc=bar'),
                new Attribute(
                    'dc',
                    'foo',
                ),
            ),
            new Entry(
                new Dn('cn=mover,ou=later,dc=foo,dc=bar'),
                new Attribute(
                    'cn',
                    'mover',
                ),
            ),
            new Entry(
                new Dn('ou=later,dc=foo,dc=bar'),
                new Attribute(
                    'ou',
                    'later',
                ),
            ),
        );
    }

    /**
     * Keeps member values as links, which is where a back-link is read from.
     */
    private function storageWithAGroup(): InMemoryStorage
    {
        return new InMemoryStorage(
            EntryFixture::allWithUuid(
                new Entry(
                    new Dn('dc=foo,dc=bar'),
                    new Attribute(
                        'dc',
                        'foo',
                    ),
                ),
                new Entry(
                    new Dn('cn=alice,dc=foo,dc=bar'),
                    new Attribute(
                        'cn',
                        'alice',
                    ),
                ),
                new Entry(
                    new Dn('cn=bob,dc=foo,dc=bar'),
                    new Attribute(
                        'cn',
                        'bob',
                    ),
                ),
                new Entry(
                    new Dn('cn=staff,dc=foo,dc=bar'),
                    new Attribute(
                        'cn',
                        'staff',
                    ),
                    new Attribute(
                        'member',
                        'cn=alice,dc=foo,dc=bar',
                    ),
                ),
            ),
            linkedAttributes: $this->fromContainer(LinkedAttributes::class),
        );
    }

    /**
     * @param iterable<string> $chunks
     *
     * @return list<string>
     */
    private function dnsIn(iterable $chunks): array
    {
        preg_match_all(
            '/^dn: (.+)$/m',
            implode(
                '',
                iterator_to_array(
                    $chunks,
                    false,
                ),
            ),
            $matches,
        );

        return $matches[1];
    }

    private function storageWithEntries(): InMemoryStorage
    {
        return EntryFixture::inMemoryStorage(
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
        );
    }
}
