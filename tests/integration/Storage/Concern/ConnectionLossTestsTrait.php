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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use PDO;

/**
 * A database connection the server loses is answered as unavailable, and replaced for the request after.
 */
trait ConnectionLossTestsTrait
{
    public function testASearchOnALostDatabaseConnectionIsAnsweredAsUnavailableAndTheNextOneReconnects(): void
    {
        $this->authenticateUser();
        $this->ldapClient()->readOrFail('cn=user,dc=foo,dc=bar');

        $this->dropTheServersDatabaseConnections();

        try {
            $this->ldapClient()->readOrFail('cn=user,dc=foo,dc=bar');
            self::fail('Expected the lost database connection to be answered as unavailable.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
        }

        self::assertSame(
            'cn=user,dc=foo,dc=bar',
            $this->ldapClient()->readOrFail('cn=user,dc=foo,dc=bar')->getDn()->toString(),
        );
    }

    public function testABindOnALostDatabaseConnectionIsAnsweredAsUnavailableAndTheSessionStaysOpen(): void
    {
        $this->authenticateUser();

        $this->dropTheServersDatabaseConnections();

        try {
            $this->authenticateUser();
            self::fail('Expected the lost database connection to be answered as unavailable.');
        } catch (BindException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
        }
        $this->authenticateUser();

        self::assertTrue($this->ldapClient()->compare(
            'cn=user,dc=foo,dc=bar',
            'cn',
            'user',
        ));
    }

    private function dropTheServersDatabaseConnections(): void
    {
        $pdo = new PDO(
            (string) getenv('MYSQL_DSN'),
            getenv('MYSQL_USER') ?: 'root',
            getenv('MYSQL_PASSWORD') ?: 'root',
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );
        $statement = $pdo->query(
            'SELECT ID FROM information_schema.PROCESSLIST WHERE DB = DATABASE() AND ID <> CONNECTION_ID()',
        );
        $ids = $statement === false
            ? []
            : $statement->fetchAll(PDO::FETCH_COLUMN);

        self::assertNotEmpty(
            $ids,
            'The server holds no connection to the test database.',
        );

        foreach ($ids as $id) {
            self::assertIsNumeric($id);
            $pdo->exec(sprintf(
                'KILL CONNECTION %d',
                (int) $id,
            ));
        }
    }
}
