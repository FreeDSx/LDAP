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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\Server\Config\Storage\SubstringIndexMode;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\SqliteReindexTestsTrait;

/**
 * SQLite serializes writes under Swoole, so every read a reindex issues has to be answered by the writer itself.
 */
final class LdapReindexSqliteSwooleTest extends LdapReindexTestCase
{
    use SqliteReindexTestsTrait;

    protected function databaseName(): string
    {
        return 'reindex-sqlite-swoole.sqlite';
    }

    /**
     * Pinned rather than auto-resolved, so the substring index under test is the same on every build.
     */
    protected function storageConfig(): StorageConfigInterface
    {
        return PdoConfig::forSqlite($this->path)
            ->setSubstringIndexMode(SubstringIndexMode::Trigram);
    }

    protected function runnerMode(): RunnerMode
    {
        return RunnerMode::Swoole;
    }
}
