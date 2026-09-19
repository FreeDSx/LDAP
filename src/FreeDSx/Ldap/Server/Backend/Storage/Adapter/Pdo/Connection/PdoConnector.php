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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoSchema;
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
        private PdoSchema $schema,
    ) {}

    /**
     * The first connection, with the schema applied when the configuration asks for it; call once, at startup.
     *
     * @throws RuntimeException when the driver's extension is not loaded
     */
    public function bootstrap(): PDO
    {
        $pdo = $this->open();

        if ($this->config->getInitializeSchema()) {
            $this->schema->apply($pdo);
        }

        return $pdo;
    }

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

        // The storage depends on both, so neither is left to the configurable driver options.
        $pdo->setAttribute(
            PDO::ATTR_ERRMODE,
            PDO::ERRMODE_EXCEPTION,
        );
        $pdo->setAttribute(
            PDO::ATTR_DEFAULT_FETCH_MODE,
            PDO::FETCH_ASSOC,
        );

        foreach ($this->config->getSessionStatements() as $statement) {
            $pdo->exec($statement);
        }

        return $pdo;
    }
}
