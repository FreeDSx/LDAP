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
 * Where a list resumes from: an assigned key, which a rename cannot disturb, or a count when a sort defines the order.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PageCursor
{
    /**
     * @param int $position The key of the last entry delivered, or the count already delivered when sorted.
     */
    private function __construct(
        public int $position,
        public bool $isOrdinal = false,
    ) {}

    public static function afterEntry(int $entryKey): self
    {
        return new self($entryKey);
    }

    /**
     * @param int $delivered Entries the sorted order has already handed over.
     */
    public static function afterSorted(int $delivered): self
    {
        return new self(
            $delivered,
            true,
        );
    }
}
