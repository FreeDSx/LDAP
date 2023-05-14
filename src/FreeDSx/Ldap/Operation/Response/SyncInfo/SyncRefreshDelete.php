<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation\Response\SyncInfo;

use FreeDSx\Ldap\Operation\Response\SyncInfoMessage;

/**
 * Represents a Sync Info Message refreshDelete choice. RFC 4533.
 *
 *     refreshDelete  [1] SEQUENCE {
 *         cookie         syncCookie OPTIONAL,
 *         refreshDone    BOOLEAN DEFAULT TRUE
 *     }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 * @see https://tools.ietf.org/html/rfc4533
 */
class SyncRefreshDelete extends SyncInfoMessage
{
    protected const VALUE_TAG = 1;

    use SyncRefreshDoneTrait;
}
