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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

/**
 * Where the values a sort key orders an entry by are stored.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum SortKeySource
{
    /**
     * The value index, under the key's own attribute.
     */
    case Values;

    /**
     * The links the entry holds, ordered by the DN of each entry it names.
     */
    case Links;

    /**
     * The links naming the entry, ordered by the DN of each entry holding one.
     */
    case Backlinks;
}
