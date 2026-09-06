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

namespace FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageSlice;

use function ceil;
use function count;
use function max;
use function min;

/**
 * One page as it fills: what it holds, what it can still take, and where the next read resumes from.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class FillingPage
{
    /**
     * @var list<Entry>
     */
    private array $entries = [];

    private int $slices = 0;

    private int $candidates = 0;

    private bool $canOverfetch = true;

    /**
     * @param ?int $pageLimit Entries the page may hold, or null when nothing bounds it.
     * @param int $widestSlice The most candidates one read may examine.
     */
    public function __construct(
        private readonly ?int $pageLimit,
        private readonly int $sizeLimit,
        private readonly int $widestSlice,
        private ?PageCursor $cursor = null,
    ) {}

    public function hasCapacity(): bool
    {
        return $this->pageLimit === null
            || count($this->entries) < $this->pageLimit;
    }

    /**
     * Whether a page this full would overflow the size limit.
     */
    public function mayExceedSizeLimit(): bool
    {
        return $this->sizeLimit > 0
            && count($this->entries) >= $this->sizeLimit;
    }

    /**
     * The next bounded read, sized to what the page still needs.
     *
     * @param bool $isFilling False when the page is full and the read only probes for a further match.
     */
    public function nextSlice(
        bool $isFilling,
        ?float $deadline,
    ): PageSlice {
        $this->slices++;

        return new PageSlice(
            $this->sliceSize($isFilling),
            $this->cursor,
            $deadline,
        );
    }

    /**
     * Records what a read cost, which is the candidates it examined rather than the entries it handed back.
     */
    public function readCandidates(int $rows): void
    {
        $this->candidates += $rows;
    }

    /**
     * Whether an entry at this position may be taken, which it may not be if the read cannot place it.
     */
    public function canPlace(?PageCursor $cursor): bool
    {
        return $cursor !== null
            || !$this->isOverfetching();
    }

    public function add(
        Entry $entry,
        ?PageCursor $cursor,
    ): void {
        $this->entries[] = $entry;
        $this->cursor = $cursor ?? $this->cursor;
    }

    /**
     * Gives up on reading further from a slice, having taken what it could.
     */
    public function abandonSlice(SliceEnd $reason): void
    {
        if ($reason === SliceEnd::Unplaceable) {
            $this->canOverfetch = false;
        }
    }

    public function advanceTo(?PageCursor $cursor): void
    {
        $this->cursor = $cursor ?? $this->cursor;
    }

    public function collected(
        bool $isResultExhausted,
        bool $hasFurtherMatch,
    ): CollectedPage {
        return new CollectedPage(
            $this->entries,
            $isResultExhausted,
            $hasFurtherMatch,
            $this->cursor,
        );
    }

    /**
     * Candidates to ask for next, scaled by what a match has cost so far once the shortfall proves too narrow.
     */
    private function sliceSize(bool $isFilling): int
    {
        $shortfall = $this->pageLimit === null
            ? $this->widestSlice
            : $this->pageLimit - ($isFilling ? count($this->entries) : 0);

        if (!$isFilling || !$this->isOverfetching()) {
            return max($shortfall, 1);
        }

        $placed = count($this->entries);
        $estimate = $placed > 0
            ? (int) ceil($shortfall * ($this->candidates / $placed))
            : $this->widestSlice;

        return max(
            min($estimate, $this->widestSlice),
            $shortfall,
            1,
        );
    }

    private function isOverfetching(): bool
    {
        return $this->canOverfetch
            && $this->slices > 1;
    }
}
