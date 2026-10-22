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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\PdoErrorFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use PDOException;

/**
 * Turns a failure that lost the database connection into a storage outage, and has the connection replaced.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ConnectionLoss
{
    public function __construct(
        private PdoConnectionProviderInterface $provider,
        private PdoErrorFactory $errors,
    ) {}

    /**
     * The failure to rethrow, which is never reissued: the outcome of a statement the connection dropped is unknown.
     */
    public function translate(PDOException $exception): StorageIoException|PDOException
    {
        if (!$this->errors->of($exception)->isConnectionLost()) {
            return $exception;
        }
        $this->provider->discard();

        return new StorageIoException(
            sprintf(
                'The connection to the database was lost: %s',
                $exception->getMessage(),
            ),
            $exception,
        );
    }
}
