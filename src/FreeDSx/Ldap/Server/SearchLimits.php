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

namespace FreeDSx\Ldap\Server;

/**
 * Groups the server-side search limit caps. Null on any field leaves it unset, and zero means no limit.
 */
final readonly class SearchLimits
{
    public function __construct(
        private ?int $maxSearchSize = null,
        private ?int $maxSearchTimeLimit = null,
        private ?int $maxSearchPageSize = null,
        private ?int $maxSearchLookthrough = null,
        private ?int $maxSearchPagedLookthrough = null,
        private ?int $maxPagingSessions = null,
        private ?int $maxLinkedValues = null,
    ) {}

    /**
     * These limits over the top of another set, for a per-identity rule that overrides only the caps it names.
     */
    public function mergedOver(self $default): self
    {
        return new self(
            maxSearchSize: $this->maxSearchSize ?? $default->maxSearchSize,
            maxSearchTimeLimit: $this->maxSearchTimeLimit ?? $default->maxSearchTimeLimit,
            maxSearchPageSize: $this->maxSearchPageSize ?? $default->maxSearchPageSize,
            maxSearchLookthrough: $this->maxSearchLookthrough ?? $default->maxSearchLookthrough,
            maxSearchPagedLookthrough: $this->maxSearchPagedLookthrough ?? $default->maxSearchPagedLookthrough,
            maxPagingSessions: $this->maxPagingSessions ?? $default->maxPagingSessions,
            maxLinkedValues: $this->maxLinkedValues ?? $default->maxLinkedValues,
        );
    }

    public function maxSearchSize(): int
    {
        return $this->maxSearchSize ?? 0;
    }

    public function maxSearchTimeLimit(): int
    {
        return $this->maxSearchTimeLimit ?? 0;
    }

    public function maxSearchPageSize(): int
    {
        return $this->maxSearchPageSize ?? 0;
    }

    public function maxSearchLookthrough(): int
    {
        return $this->maxSearchLookthrough ?? 0;
    }

    public function maxPagingSessions(): ?int
    {
        return $this->maxPagingSessions;
    }

    /**
     * Values of a linked attribute returned per entry: null when unset, so the storage default applies, and zero for all.
     */
    public function maxLinkedValues(): ?int
    {
        return $this->maxLinkedValues;
    }

    /**
     * Effective lookthrough for paged searches: the paged limit when set, otherwise the regular lookthrough.
     */
    public function effectivePagedLookthrough(): int
    {
        return ($this->maxSearchPagedLookthrough ?? 0) > 0
            ? $this->maxSearchPagedLookthrough ?? 0
            : $this->maxSearchLookthrough();
    }
}
