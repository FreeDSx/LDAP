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

use FreeDSx\Ldap\Entry\Entries;

/**
 * Represents the paging response to be returned from a client paging request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PagingResponse
{
    public function __construct(
        private readonly Entries $entries,
        private readonly bool $isComplete = false,
        private readonly int $remaining = 0
    ) {
    }

    public function getEntries(): Entries
    {
        return $this->entries;
    }

    public function getRemaining(): int
    {
        return $this->remaining;
    }

    public function isComplete(): bool
    {
        return $this->isComplete;
    }

    /**
     * Make a standard paging response that indicates that are still results left to return.
     *
     * @param Entries $entries The entries returned for this response.
     * @param int $remaining The number of entries left (if known)
     */
    public static function make(
        Entries $entries,
        int $remaining = 0
    ): self {
        return new self(
            $entries,
            false,
            $remaining
        );
    }

    /**
     * Make a final paging response indicating that there are no more entries left to return.
     */
    public static function makeFinal(Entries $entries): self
    {
        return new self(
            $entries,
            true
        );
    }
}
