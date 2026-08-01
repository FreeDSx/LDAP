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
 * Builds the draft-behera-ldap-password-policy-10 definitions, read from resources/ldap-schema/ppolicy.ldif.
 */
final class PasswordPolicySchemaProvider
{
    private function __construct() {}

    /**
     * @throws SchemaParseException
     */
    public static function build(): Schema
    {
        return SchemaResource::PasswordPolicy->load();
    }
}
