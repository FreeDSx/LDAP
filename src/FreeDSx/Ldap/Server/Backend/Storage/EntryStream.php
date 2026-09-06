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

use FreeDSx\Ldap\Entry\Entry;
use Generator;

/**
 * Lazy entries from storage. Single use only.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryStream
{
    /**
     * @param Generator<int, Entry|FetchedEntry, mixed, ?FetchedBatch> $stream Returns what it read, once read to its end.
     * @param bool $isPreFiltered marks an exact native filter match.
     */
    private function __construct(
        private Generator $stream,
        private bool $isPositioned,
        public bool $isPreFiltered = false,
    ) {}

    /**
     * Entries alone, for a read with no position to resume from.
     *
     * @param Generator<int, Entry, mixed, ?FetchedBatch> $entries
     */
    public static function of(
        Generator $entries,
        bool $isPreFiltered = false,
    ): self {
        return new self(
            $entries,
            false,
            $isPreFiltered,
        );
    }

    /**
     * Entries that each carry the point a later read resumes from.
     *
     * @param Generator<int, FetchedEntry, mixed, ?FetchedBatch> $entries
     */
    public static function positioned(
        Generator $entries,
        bool $isPreFiltered = false,
    ): self {
        return new self(
            $entries,
            true,
            $isPreFiltered,
        );
    }

    /**
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     */
    public function entries(): Generator
    {
        if (!$this->isPositioned) {
            /** @var Generator<int, Entry, mixed, ?FetchedBatch> */
            return $this->stream;
        }

        return $this->unwrapped();
    }

    /**
     * @return Generator<int, FetchedEntry, mixed, ?FetchedBatch>
     */
    public function fetched(): Generator
    {
        if ($this->isPositioned) {
            /** @var Generator<int, FetchedEntry, mixed, ?FetchedBatch> */
            return $this->stream;
        }

        return $this->positionless();
    }

    /**
     * @return Generator<int, Entry, mixed, ?FetchedBatch>
     */
    private function unwrapped(): Generator
    {
        foreach ($this->stream as $fetched) {
            /** @var FetchedEntry $fetched */
            yield $fetched->entry;
        }

        return $this->stream->getReturn();
    }

    /**
     * @return Generator<int, FetchedEntry, mixed, ?FetchedBatch>
     */
    private function positionless(): Generator
    {
        foreach ($this->stream as $entry) {
            /** @var Entry $entry */
            yield new FetchedEntry($entry);
        }

        return $this->stream->getReturn();
    }
}
