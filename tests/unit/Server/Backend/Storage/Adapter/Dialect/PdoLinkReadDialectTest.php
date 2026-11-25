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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\LinkKeys;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PdoLinkReadDialectTest extends TestCase
{
    #[DataProvider('orderedReadProvider')]
    public function test_a_read_of_links_in_order_puts_two_uids_of_one_target_in_order(string $sql): void
    {
        self::assertStringContainsString(
            'l.target_entry_id, l.target_uid',
            $sql,
        );
    }

    /**
     * @return Generator<string, array{string}>
     */
    public static function orderedReadProvider(): Generator
    {
        $owners = LinkKeys::span(
            1,
            3,
        );

        foreach (['sqlite' => new SqliteDialect(), 'mysql' => new MysqlDialect()] as $driver => $dialect) {
            yield "$driver: the links of some owners" => [$dialect->queryLinksFor($owners)];
            yield "$driver: the links of some owners but a few attributes" => [$dialect->queryLinksForExcept(
                $owners,
                1,
            )];
            yield "$driver: one slice of an attribute" => [$dialect->queryLinksForAttributeFrom()];
        }
    }
}
