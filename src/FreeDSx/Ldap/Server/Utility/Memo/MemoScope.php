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

namespace FreeDSx\Ldap\Server\Utility\Memo;

/**
 * How long a memo lives, which decides what it does once it is full.
 *
 * @internal
 */
enum MemoScope
{
    /**
     * Lives as long as the process and empties when full.
     */
    case Process;

    /**
     * Lives for one request or filter and keeps its first answers when full.
     */
    case Request;
}
