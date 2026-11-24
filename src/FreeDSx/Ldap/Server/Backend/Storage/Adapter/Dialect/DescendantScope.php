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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;

/**
 * How a subtree rename or an unfiltered subtree listing finds the entries beneath its base.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum DescendantScope
{
    /**
     * Descends stored parent links, which costs the subtree but misses an entry whose parent is not stored.
     */
    case ParentLinks;

    /**
     * Takes every DN ending in the base's, which reads the whole table.
     */
    case DnSuffix;

    /**
     * The value the scope's condition binds for the base.
     */
    public function bindingFor(string $lcBase): string
    {
        return match ($this) {
            self::ParentLinks => $lcBase,
            self::DnSuffix => '%,' . SqlFilterUtility::escape($lcBase),
        };
    }
}
