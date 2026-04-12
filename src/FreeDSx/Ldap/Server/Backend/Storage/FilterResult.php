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

namespace FreeDSx\Ldap\Server\Backend\Storage;

/**
 * RFC 4511 three-valued filter result.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum FilterResult
{
    case True;
    case False;
    case Undefined;
}
