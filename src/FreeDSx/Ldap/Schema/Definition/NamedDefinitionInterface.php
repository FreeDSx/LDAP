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

namespace FreeDSx\Ldap\Schema\Definition;

/**
 * A schema definition identified by an OID and any number of names.
 *
 * @api
 */
interface NamedDefinitionInterface
{
    /**
     * The first name the definition is known by, or its OID when it has none.
     */
    public function primaryName(): string;
}
