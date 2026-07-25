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

namespace Tests\Support\FreeDSx\Ldap\Server\PasswordPolicy\Replica;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoReplicaPasswordStateStore;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use PDO;

/**
 * Builds the real replica password-policy state store over a throwaway in-memory SQLite database.
 */
final class SqliteReplicaPasswordStateStoreFactory
{
    public static function inMemory(): PdoReplicaPasswordStateStore
    {
        $pdo = new PDO('sqlite::memory:');
        $dialect = new SqliteDialect();
        PdoStorage::initialize(
            $pdo,
            $dialect,
        );
        $provider = new SharedPdoConnectionProvider(
            $pdo,
            static fn(): PDO => $pdo,
        );

        return new PdoReplicaPasswordStateStore(
            new PdoTransactor(
                $provider,
                $dialect,
            ),
            $dialect,
            new PdoStatementPool($provider),
        );
    }
}
