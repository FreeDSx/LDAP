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

namespace FreeDSx\Ldap\Protocol;

/**
 * What became of a message that failed to decode.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum DecodeFailureOutcome
{
    /**
     * A response was sent on the message's ID.
     */
    case Answered;

    /**
     * A refused request that takes no response was recorded and dropped.
     */
    case Dropped;

    /**
     * It cannot be answered and ends the session.
     */
    case Unanswerable;
}
