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

namespace FreeDSx\Ldap\Exception;

use function count;
use function implode;
use function sprintf;

/**
 * Thrown when a replica cannot move aside an entry in the way of another, or an entry it moved aside is never placed again.
 */
class UnresolvedReplicaMovesException extends RuntimeException
{
    /**
     * @param list<string> $dns The DNs the entries could not be placed at or moved aside from.
     */
    public function __construct(public readonly array $dns)
    {
        parent::__construct(sprintf(
            '%d replicated entry placement(s) could not be resolved: %s',
            count($dns),
            implode('; ', $dns),
        ));
    }
}
