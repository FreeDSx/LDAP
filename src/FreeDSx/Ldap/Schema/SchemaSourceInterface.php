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
 * Something the server can read schema definitions from.
 *
 * Definitions are returned as parsed; cross-references are checked once the sources have been merged, so a source
 * may reference definitions another source provides.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SchemaSourceInterface
{
    /**
     * @throws SchemaParseException
     */
    public function load(): Schema;
}
