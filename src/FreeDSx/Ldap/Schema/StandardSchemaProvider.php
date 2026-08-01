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

namespace FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Exception\SchemaParseException;

/**
 * Builds the core Schema with RFC 4517/4519/4512 standard definitions, read from resources/ldap-schema/core.ldif.
 */
final class StandardSchemaProvider
{
    private function __construct() {}

    /**
     * @throws SchemaParseException
     */
    public static function buildCore(): Schema
    {
        return SchemaResource::Core->load();
    }
}
