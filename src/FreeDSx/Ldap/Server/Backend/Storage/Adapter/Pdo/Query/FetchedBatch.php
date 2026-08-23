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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query;

use FreeDSx\Ldap\Server\Backend\Storage\PageCursor;

/**
 * What one statement's worth of rows amounted to.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FetchedBatch
{
    /**
     * @param int $rows Rows read, which tells a caller whether the batch filled and so whether more may follow.
     * @param ?PageCursor $cursor Where the rows ended, or null when none were read.
     */
    public function __construct(
        public int $rows,
        public ?PageCursor $cursor = null,
    ) {}
}
