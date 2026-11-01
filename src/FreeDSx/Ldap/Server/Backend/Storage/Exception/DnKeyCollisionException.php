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

namespace FreeDSx\Ldap\Server\Backend\Storage\Exception;

use FreeDSx\Ldap\Exception\RuntimeException;
use Throwable;

/**
 * Thrown when rebuilding the stored DN keys finds two entries whose DNs now normalize to the same key.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DnKeyCollisionException extends RuntimeException
{
    public function __construct(
        string $dn,
        string $otherDn,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            sprintf(
                'The entries "%s" and "%s" now share one DN key; rename one of them and reindex again.',
                $dn,
                $otherDn,
            ),
            0,
            $previous,
        );
    }
}
