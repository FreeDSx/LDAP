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
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Link\LinkSpanReader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDirection;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;

final class LinkSpanReaderTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private const GROUP = 'cn=admins,dc=example,dc=com';

    private const MEMBER = 'cn=alice,dc=example,dc=com';

    private const STAFF = 'cn=staff,dc=example,dc=com';

    private const SECOND_MEMBER = 'cn=bob,dc=example,dc=com';

    private LinkSpanReader $backward;

    private LinkSpanReader $forward;

    private EntryWriter $storage;

    private PdoConnection $connection;

    protected function setUp(): void
    {
        $pdo = new PDO('sqlite::memory:');
        (new PdoSchema(new SqliteDialect()))->apply($pdo);

        $container = Container::forServer(
            TestServerOptions::sqlite(),
            [PdoConnectionProviderInterface::class => new SharedPdoConnectionProvider($pdo)],
        );
        $this->storage = $container->get(EntryWriter::class);
        $this->connection = $container->get(PdoConnection::class);
        $dialect = $container->get(PdoDialectInterface::class);
        $linked = new LinkedAttributes(SchemaResource::Core->load()->addAttributeType(new AttributeType(
            '1.400',
            ['isMemberOf'],
            noUserModification: true,
            extensions: [AttributeType::EXTENSION_LINKED_BY => ['member']],
        )));
        $this->backward = new LinkSpanReader(
            $dialect,
            $this->connection,
            LinkDirection::Backward,
            $linked,
        );
        $this->forward = new LinkSpanReader(
            $dialect,
            $this->connection,
            LinkDirection::Forward,
            $linked,
        );

        $this->seed();
    }

    public function test_it_reads_values_back_under_every_backlink_reversing_the_attribute(): void
    {
        self::assertSame(
            [
                'memberOf' => [self::GROUP],
                'isMemberOf' => [self::GROUP],
            ],
            $this->backward->forSpan(...$this->spanOf(self::MEMBER))[$this->entryIdOf(self::MEMBER)] ?? [],
        );
    }

    public function test_an_entry_nothing_names_reads_back_nothing(): void
    {
        self::assertSame(
            [],
            $this->backward->forSpan(...$this->spanOf(self::GROUP))[$this->entryIdOf(self::GROUP)] ?? [],
        );
    }

    public function test_reading_forwards_names_each_attribute_as_the_schema_does(): void
    {
        self::assertSame(
            [
                'member' => [self::MEMBER],
                'seeAlso' => [self::MEMBER],
            ],
            $this->forward->forSpan(...$this->spanOf(self::GROUP))[$this->entryIdOf(self::GROUP)] ?? [],
        );
    }

    public function test_a_linked_attribute_over_the_cap_is_ranged_under_its_schema_name(): void
    {
        $this->seedStaff();

        self::assertSame(
            [
                'member;range=0-0' => [self::MEMBER],
                'seeAlso;range=0-0' => [self::MEMBER],
            ],
            $this->cappedAtOne(
                $this->forward,
                self::STAFF,
            ),
        );
    }

    public function test_a_backlink_over_the_cap_is_ranged_under_its_schema_name(): void
    {
        $this->seedStaff();

        self::assertSame(
            [
                'isMemberOf;range=0-0' => [self::GROUP],
                'memberOf;range=0-0' => [self::GROUP],
            ],
            $this->cappedAtOne(
                $this->backward,
                self::MEMBER,
            ),
        );
    }

    /**
     * @return array<string, list<string>>
     */
    private function cappedAtOne(
        LinkSpanReader $reader,
        string $dn,
    ): array {
        $id = $this->entryIdOf($dn);
        $links = $reader->forSpan(
            $id,
            $id,
            1,
        )[$id] ?? [];
        ksort($links);

        return $links;
    }

    /**
     * @return array{int, int, int}
     */
    private function spanOf(string $dn): array
    {
        $id = $this->entryIdOf($dn);

        return [$id, $id, 1500];
    }

    private function entryIdOf(string $dn): int
    {
        $row = $this->connection
            ->execute(
                'SELECT entry_id FROM entries WHERE lc_dn = ?',
                [(new Dn($dn))->normalizedString()],
            )
            ->fetch();
        $id = is_array($row)
            ? $row['entry_id'] ?? null
            : null;

        return is_numeric($id)
            ? (int) $id
            : 0;
    }

    private function seed(): void
    {
        $this->storage->store(EntryFixture::withUuid(new Entry(
            new Dn(self::BASE),
            new Attribute('dc', 'example'),
        )));
        $this->storage->store(EntryFixture::withUuid(new Entry(
            new Dn(self::MEMBER),
            new Attribute('cn', 'alice'),
        )));
        $this->storage->store(EntryFixture::withUuid(new Entry(
            new Dn(self::GROUP),
            new Attribute('cn', 'admins'),
            new Attribute('member', self::MEMBER),
            new Attribute('seealso', self::MEMBER),
        )));
    }

    private function seedStaff(): void
    {
        $this->storage->store(EntryFixture::withUuid(new Entry(
            new Dn(self::SECOND_MEMBER),
            new Attribute('cn', 'bob'),
        )));
        $this->storage->store(EntryFixture::withUuid(new Entry(
            new Dn(self::STAFF),
            new Attribute('cn', 'staff'),
            new Attribute('member', self::MEMBER, self::SECOND_MEMBER),
            new Attribute('seealso', self::MEMBER, self::SECOND_MEMBER),
        )));
    }
}
