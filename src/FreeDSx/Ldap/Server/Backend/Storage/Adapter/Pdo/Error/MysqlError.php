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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error;

use function str_ends_with;

/**
 * A MySQL or MariaDB failure, read from its error code and, for a duplicate, the key that refused it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class MysqlError implements PdoErrorInterface
{
    /**
     * Deadlock found when trying to get lock, which has already rolled the transaction back.
     */
    private const ERROR_DEADLOCK = 1213;

    /**
     * Lock wait timeout exceeded.
     */
    private const ERROR_LOCK_WAIT_TIMEOUT = 1205;

    /**
     * Duplicate entry for key.
     */
    private const ERROR_DUPLICATE_ENTRY = 1062;

    /**
     * Data too long for a column.
     */
    private const ERROR_DATA_TOO_LONG = 1406;

    /**
     * Errors after which the connection is gone, whether the client lost it or the server ended it.
     */
    private const CONNECTION_LOST_ERRORS = [
        // Server shutdown in progress.
        1053,
        // MariaDB: the connection was killed.
        1927,
        // Cannot connect through the local socket.
        2002,
        // Cannot connect to the host.
        2003,
        // The server has gone away.
        2006,
        // Lost connection during a query.
        2013,
        // Lost connection, with the system error.
        2055,
        // Disconnected by the server after an idle timeout.
        4031,
    ];

    public function __construct(private DriverErrorInfo $info) {}

    /**
     * InnoDB resolves lock conflicts by failing one transaction, which is then safe to reissue unchanged.
     */
    public function isRetryableConflict(): bool
    {
        return $this->info->hasDriverCode(
            self::ERROR_DEADLOCK,
            self::ERROR_LOCK_WAIT_TIMEOUT,
        );
    }

    public function isDuplicateDn(): bool
    {
        return $this->isDuplicateOnKey('uq_lc_dn');
    }

    public function isDuplicateEntryUuid(): bool
    {
        return $this->isDuplicateOnKey('uq_entry_uuid');
    }

    public function isValueTooLong(): bool
    {
        return $this->info->hasDriverCode(self::ERROR_DATA_TOO_LONG);
    }

    public function isConnectionLost(): bool
    {
        return $this->info->isConnectionException()
            || $this->info->hasDriverCode(...self::CONNECTION_LOST_ERRORS);
    }

    /**
     * The message ends with the key name, which MySQL prefixes with the table and MariaDB does not.
     */
    private function isDuplicateOnKey(string $key): bool
    {
        $message = $this->info->driverMessage();

        return $this->info->hasDriverCode(self::ERROR_DUPLICATE_ENTRY)
            && $message !== null
            && str_ends_with($message, $key . "'");
    }
}
