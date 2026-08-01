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
 * Builds the RFC 2307 POSIX account/group/shadow schema, read from resources/ldap-schema/nis.ldif.
 *
 * @api
 */
final class NisSchemaProvider
{
    private function __construct() {}

    /**
     * @throws SchemaParseException
     */
    public static function build(): Schema
    {
        return SchemaResource::Nis->load();
    }
}
