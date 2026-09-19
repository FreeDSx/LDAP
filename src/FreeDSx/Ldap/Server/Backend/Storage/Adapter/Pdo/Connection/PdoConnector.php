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

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\PdoStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use PDO;

/**
 * Opens connections to the configured database, ready for the storage to use.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PdoConnector
{
    public function __construct(
        private PdoConfig $config,
        private PdoDialectInterface $dialect,
        private SubstringIndexInterface $substringIndex,
    ) {}

    /**
     * @throws RuntimeException when the driver's extension is not loaded
     */
    public function open(): PDO
    {
        $extension = $this->config->getDriver()->extension();

        if (!extension_loaded($extension)) {
            throw new RuntimeException(sprintf(
                'The "%s" extension is required for this PDO storage backend.',
                $extension,
            ));
        }

        $pdo = new PDO(
            $this->config->getDsn(),
            $this->config->getUsername(),
            $this->config->getPassword(),
            $this->config->getPdoOptions(),
        );

        foreach ($this->config->getSessionStatements() as $statement) {
            $pdo->exec($statement);
        }

        if ($this->config->getInitializeSchema()) {
            PdoStorage::initialize(
                $pdo,
                $this->dialect,
                $this->substringIndex,
            );
        }

        return $pdo;
    }
}
