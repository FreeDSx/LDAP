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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\MysqlDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\SqliteDialect;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\Fts5SubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\TrigramSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Config\StorageConfigInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Config\StorageType;
use PDO;
use SensitiveParameter;

/**
 * Full connection + options for a PdoStorage; build one with forSqlite()/forMysql() and tune it with the setters.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoConfig implements StorageConfigInterface
{
    /**
     * @param array<int, mixed> $pdoOptions
     * @param list<string> $sessionStatements
     */
    private function __construct(
        private PdoDialectInterface $dialect,
        private string $dsn,
        private ?string $username,
        private ?string $password,
        private array $pdoOptions,
        private array $sessionStatements,
        private bool $serializeSwooleWrites,
        private string $driverExtension,
        private bool $initializeSchema = true,
        private ?SubstringIndexInterface $substringIndex = new TrigramSubstringIndex(),
    ) {}

    public static function forSqlite(string $path): self
    {
        return new self(
            dialect: new SqliteDialect(),
            dsn: 'sqlite:' . $path,
            username: null,
            password: null,
            pdoOptions: [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            sessionStatements: [
                'PRAGMA busy_timeout = 5000',
                'PRAGMA synchronous = NORMAL',
                'PRAGMA journal_mode = WAL',
                'PRAGMA foreign_keys = ON',
            ],
            serializeSwooleWrites: true,
            driverExtension: 'pdo_sqlite',
            substringIndex: Fts5SubstringIndex::isSupported()
                ? new Fts5SubstringIndex()
                : new TrigramSubstringIndex(),
        );
    }

    public static function forMysql(
        string $dsn,
        #[SensitiveParameter]
        string $username,
        #[SensitiveParameter]
        string $password,
    ): self {
        return new self(
            dialect: new MysqlDialect(),
            dsn: $dsn,
            username: $username,
            password: $password,
            pdoOptions: [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ],
            sessionStatements: [
                'SET NAMES utf8mb4',
                "SET time_zone = '+00:00'",
            ],
            serializeSwooleWrites: false,
            driverExtension: 'pdo_mysql',
        );
    }

    /**
     * Generic constructor for a custom database engine; tune username/password/pdoOptions/sessionStatements via the setters.
     */
    public static function forDriver(
        PdoDialectInterface $dialect,
        string $dsn,
        string $driverExtension,
    ): self {
        return new self(
            dialect: $dialect,
            dsn: $dsn,
            username: null,
            password: null,
            pdoOptions: [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
            sessionStatements: [],
            serializeSwooleWrites: false,
            driverExtension: $driverExtension,
        );
    }

    public function getDialect(): PdoDialectInterface
    {
        return $this->dialect;
    }

    public function setDialect(PdoDialectInterface $dialect): self
    {
        $this->dialect = $dialect;

        return $this;
    }

    public function getDsn(): string
    {
        return $this->dsn;
    }

    public function setDsn(string $dsn): self
    {
        $this->dsn = $dsn;

        return $this;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(?string $username): self
    {
        $this->username = $username;

        return $this;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(
        #[SensitiveParameter]
        ?string $password,
    ): self {
        $this->password = $password;

        return $this;
    }

    /**
     * @return array<int, mixed>
     */
    public function getPdoOptions(): array
    {
        return $this->pdoOptions;
    }

    /**
     * @param array<int, mixed> $pdoOptions
     */
    public function setPdoOptions(array $pdoOptions): self
    {
        $this->pdoOptions = $pdoOptions;

        return $this;
    }

    /**
     * @return list<string>
     */
    public function getSessionStatements(): array
    {
        return $this->sessionStatements;
    }

    /**
     * @param list<string> $sessionStatements
     */
    public function setSessionStatements(array $sessionStatements): self
    {
        $this->sessionStatements = $sessionStatements;

        return $this;
    }

    public function getSerializeSwooleWrites(): bool
    {
        return $this->serializeSwooleWrites;
    }

    public function setSerializeSwooleWrites(bool $serializeSwooleWrites): self
    {
        $this->serializeSwooleWrites = $serializeSwooleWrites;

        return $this;
    }

    public function getDriverExtension(): string
    {
        return $this->driverExtension;
    }

    public function setDriverExtension(string $driverExtension): self
    {
        $this->driverExtension = $driverExtension;

        return $this;
    }

    public function getInitializeSchema(): bool
    {
        return $this->initializeSchema;
    }

    public function setInitializeSchema(bool $initializeSchema): self
    {
        $this->initializeSchema = $initializeSchema;

        return $this;
    }

    public function getSubstringIndex(): ?SubstringIndexInterface
    {
        return $this->substringIndex;
    }

    public function setSubstringIndex(?SubstringIndexInterface $substringIndex): self
    {
        $this->substringIndex = $substringIndex;

        return $this;
    }

    public function type(): StorageType
    {
        return StorageType::Pdo;
    }
}
