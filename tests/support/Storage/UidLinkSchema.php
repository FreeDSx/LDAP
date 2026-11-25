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

namespace Tests\Support\FreeDSx\Ldap\Storage;

use FreeDSx\Ldap\Schema\LdifSchemaSource;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

/**
 * The core schema plus a linked attribute whose values carry an optional uid after the name they link.
 */
final class UidLinkSchema
{
    public const ATTRIBUTE = 'uidLink';

    private const LDIF = __DIR__ . '/../../resources/schema/uid-link.ldif';

    public static function load(): Schema
    {
        return SchemaResource::Core->load()->merge((new LdifSchemaSource(self::LDIF))->load());
    }

    public static function options(StorageConfigInterface $storage): ServerOptions
    {
        return TestServerOptions::unvalidated(
            SchemaResource::Core,
            new LdifSchemaSource(self::LDIF),
        )->setStorageConfig($storage);
    }
}
