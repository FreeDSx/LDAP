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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Link\LinkSpanReader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer\EntryWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDirection;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\Backlinks;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class LinkSpanReaderTest extends TestCase
{
    private const BASE = 'dc=example,dc=com';

    private const GROUP = 'cn=admins,dc=example,dc=com';

    private const MEMBER = 'cn=alice,dc=example,dc=com';

    private LinkSpanReader $subject;

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
        $reversing = [
            'memberof' => 'member',
            'ismemberof' => 'member',
        ];
        $this->subject = new LinkSpanReader(
            $container->get(PdoDialectInterface::class),
            $this->connection,
            LinkDirection::Backward,
            new Backlinks($reversing, $reversing),
        );

        $this->seed();
    }

    public function test_it_reads_values_back_under_every_backlink_reversing_the_attribute(): void
    {
        self::assertSame(
            [
                'memberof' => [self::GROUP],
                'ismemberof' => [self::GROUP],
            ],
            $this->subject->forSpan(...$this->spanOf(self::MEMBER))[$this->entryIdOf(self::MEMBER)] ?? [],
        );
    }

    public function test_an_entry_nothing_names_reads_back_nothing(): void
    {
        self::assertSame(
            [],
            $this->subject->forSpan(...$this->spanOf(self::GROUP))[$this->entryIdOf(self::GROUP)] ?? [],
        );
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
        $this->storage->store(new Entry(
            new Dn(self::BASE),
            new Attribute('dc', 'example'),
        ));
        $this->storage->store(new Entry(
            new Dn(self::MEMBER),
            new Attribute('cn', 'alice'),
        ));
        $this->storage->store(new Entry(
            new Dn(self::GROUP),
            new Attribute('cn', 'admins'),
            new Attribute('member', self::MEMBER),
        ));
    }
}
