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

namespace FreeDSx\Ldap\Server\Backend\Storage\Link;

/**
 * Which way a link is read: from the entry holding the values, or from the entry they name.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum LinkDirection
{
    case Forward;

    case Backward;
}
