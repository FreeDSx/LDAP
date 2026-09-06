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

use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;

/**
 * What one bounded read amounted to, returned by the stream that performed it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FetchedBatch
{
    /**
     * @param int $rows Candidates read, which tells a caller whether its bound was reached.
     * @param ?PageCursor $cursor The last one read, or null when there were none.
     * @param bool $hasMore Whether a further candidate was seen beyond the bound, so a caller need not read to find out.
     */
    public function __construct(
        public int $rows,
        public ?PageCursor $cursor = null,
        public bool $hasMore = false,
    ) {}

    /**
     * Whether the result ended here, either because nothing follows or because there is no position to resume from.
     */
    public function isExhausted(): bool
    {
        return !$this->hasMore
            || $this->cursor === null;
    }
}
