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

/**
 * How a loader reacts to a definition it cannot parse or whose references it cannot resolve.
 *
 * @api
 */
enum SchemaLoadMode
{
    /**
     * Any unparsable definition or unresolved reference fails the load.
     */
    case Strict;

    /**
     * An unparsable definition is skipped and an unresolved reference is kept as-is.
     */
    case Lenient;
}
