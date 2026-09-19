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

namespace FreeDSx\Ldap\Server\Backend\Storage\Search\Options;

use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageSlice;

/**
 * How far a list may go: when it must stop, how many candidates it may examine, and which slice it reads.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReadBounds
{
    /**
     * @param ?float $deadline When the read must stop, or null for no time bound.
     * @param int $lookthroughLimit Candidates the read may examine, or zero for no bound.
     * @param ?PageSlice $slice Where to resume and how many candidates to hand over, or null for the whole result.
     */
    public function __construct(
        public ?float $deadline = null,
        public int $lookthroughLimit = 0,
        private ?PageSlice $slice = null,
    ) {}

    /**
     * Candidates this read may hand over, or null when it is not bounded to a slice.
     */
    public function limit(): ?int
    {
        return $this->slice?->limit;
    }

    /**
     * Where to resume, or null to start from the beginning.
     */
    public function resumeAfter(): ?PageCursor
    {
        return $this->slice?->after;
    }
}
