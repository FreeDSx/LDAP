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

namespace FreeDSx\Ldap\Server\Metrics\Observation;

/**
 * The outcome of a change-journal related operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum JournalObservation: string
{
    case PruneSucceeded = 'prune_succeeded';

    case PruneFailed = 'prune_failed';
}
