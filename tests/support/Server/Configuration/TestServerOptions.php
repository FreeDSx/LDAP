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

namespace Tests\Support\FreeDSx\Ldap\Server\Configuration;

use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\SchemaSourceInterface;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use FreeDSx\Ldap\Server\Config\Storage\InMemoryStorageConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * Configuration presets for tests, so the container is the only thing assembling services.
 */
final class TestServerOptions
{
    public const TEST_HASH_COST = 4;

    /**
     * What a test asserting on storage or filter semantics wants, rather than on schema enforcement.
     */
    public static function unvalidatedCore(): ServerOptions
    {
        return self::unvalidated(SchemaResource::Core);
    }

    /**
     * Core definitions enforced at the given mode, for a test asserting on schema enforcement itself.
     */
    public static function validatedCore(SchemaValidationMode $mode): ServerOptions
    {
        return new ServerOptions(
            self::transientStorage(),
            schemaConfig: (new SchemaConfig())
                ->setSources(SchemaResource::Core)
                ->setValidationMode($mode),
        );
    }

    /**
     * Sources merge in order, so a later one may build on an earlier one.
     */
    public static function unvalidated(SchemaSourceInterface ...$sources): ServerOptions
    {
        return new ServerOptions(
            self::transientStorage(),
            schemaConfig: self::unvalidatedCoreSchema()
                ->setSources(...$sources),
        );
    }

    /**
     * A transient database, which is what a storage test wants unless it needs one that outlives the connection.
     */
    public static function sqlite(): ServerOptions
    {
        return self::forStorage(PdoConfig::forSqlite(':memory:'));
    }

    /**
     * Stock options on transient storage, for a test that cares about neither.
     */
    public static function defaults(): ServerOptions
    {
        return new ServerOptions(self::transientStorage());
    }

    /**
     * What a test wants when it asserts on something other than storage; nothing outlives the test.
     */
    public static function transientStorage(): StorageConfigInterface
    {
        return InMemoryStorageConfig::withEntries();
    }

    /**
     * The given storage, for a test that has to configure the adapter itself.
     */
    public static function forStorage(StorageConfigInterface $storageConfig): ServerOptions
    {
        return new ServerOptions(
            $storageConfig,
            schemaConfig: self::unvalidatedCoreSchema(),
        );
    }

    /**
     * The lowest bcrypt cost, since hashing at the production factor dominates the runtime of a password test.
     */
    public static function cheaplyHashed(): ServerOptions
    {
        return new ServerOptions(
            self::transientStorage(),
            schemaConfig: self::unvalidatedCoreSchema(),
            passwordConfig: (new PasswordConfig())->setHashCost(self::TEST_HASH_COST),
        );
    }

    private static function unvalidatedCoreSchema(): SchemaConfig
    {
        return (new SchemaConfig())
            ->setSources(SchemaResource::Core)
            ->setValidationMode(SchemaValidationMode::Off);
    }
}
