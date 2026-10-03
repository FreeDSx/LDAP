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
 * Thrown when a replica cannot place moved entries at their new DNs without deleting the entries holding them.
 */
class UnresolvedReplicaMovesException extends RuntimeException
{
    /**
     * @param list<string> $dns The new DNs the moved entries could not be placed at.
     */
    public function __construct(public readonly array $dns)
    {
        parent::__construct(sprintf(
            '%d replicated move(s) could not be placed, as another entry holds the new DN: %s',
            count($dns),
            implode('; ', $dns),
        ));
    }
}
