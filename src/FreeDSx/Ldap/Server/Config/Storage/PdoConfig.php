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

namespace FreeDSx\Ldap\Server\Config\Storage;

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
     * @var array<int, mixed>
     */
    private array $pdoOptions;

    /**
     * @var list<string>
     */
    private array $sessionStatements;

    private bool $serializeSwooleWrites;

    private bool $initializeSchema = true;

    private SubstringIndexMode $substringIndexMode = SubstringIndexMode::Auto;

    private function __construct(
        private readonly PdoDriver $driver,
        private string $dsn,
        private ?string $username = null,
        #[SensitiveParameter]
        private ?string $password = null,
    ) {
        $this->pdoOptions = $driver->defaultPdoOptions();
        $this->sessionStatements = $driver->defaultSessionStatements();
        $this->serializeSwooleWrites = $driver->serializesWrites();
    }

    public static function forSqlite(string $path): self
    {
        return new self(
            PdoDriver::Sqlite,
            'sqlite:' . $path,
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
            PdoDriver::Mysql,
            $dsn,
            $username,
            $password,
        );
    }

    /**
     * The database engine; it selects the dialect, filter translator and driver extension.
     */
    public function getDriver(): PdoDriver
    {
        return $this->driver;
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

    public function getInitializeSchema(): bool
    {
        return $this->initializeSchema;
    }

    public function setInitializeSchema(bool $initializeSchema): self
    {
        $this->initializeSchema = $initializeSchema;

        return $this;
    }

    public function getSubstringIndexMode(): SubstringIndexMode
    {
        return $this->substringIndexMode;
    }

    public function setSubstringIndexMode(SubstringIndexMode $substringIndexMode): self
    {
        $this->substringIndexMode = $substringIndexMode;

        return $this;
    }

    public function type(): StorageType
    {
        return StorageType::Pdo;
    }

    /**
     * A SQLite in-memory database belongs to the connection that opened it, so each process would get its own.
     */
    public function isMultiProcessSafe(): bool
    {
        if ($this->driver !== PdoDriver::Sqlite) {
            return StorageType::Pdo->isMultiProcessSafe();
        }

        $dsn = strtolower($this->dsn);

        return !str_contains($dsn, ':memory:')
            && !str_contains($dsn, 'mode=memory');
    }
}
