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

namespace FreeDSx\Ldap\Server\Subentry;

/**
 * Which of the two entry populations a one-level or subtree search selects. RFC 3672.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum SubentryVisibility
{
    /**
     * Ordinary entries only, the default when no subentries control is present.
     */
    case Hide;

    /**
     * Subentries only, requested by the subentries control with a TRUE value.
     */
    case Only;

    /**
     * Both populations. Never selectable over the protocol; used by replication and internal lookups.
     */
    case All;
}
