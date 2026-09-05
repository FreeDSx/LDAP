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

namespace FreeDSx\Ldap\Server\Backend\Storage\Paging;

/**
 * A bounded piece of a result, for a caller that reads one page at a time.
 *
 * Bounded so the caller can read it to the end, which is the only point a stream will say where it stopped.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PageSlice
{
    /**
     * @param int $limit Candidates this slice may examine.
     * @param ?PageCursor $after Where to resume, or null to start from the beginning.
     * @param ?float $deadline When the page this slice belongs to runs out of time.
     */
    public function __construct(
        public int $limit,
        public ?PageCursor $after = null,
        public ?float $deadline = null,
    ) {}
}
