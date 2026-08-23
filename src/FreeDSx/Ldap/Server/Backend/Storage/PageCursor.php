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

/**
 * Where a list resumes from, as a key the storage assigns rather than anything derived from the entry.
 *
 * A key survives a rename, so a walk is not disturbed by one landing between pages.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PageCursor
{
    /**
     * @param int $entryKey Identifies the last entry delivered.
     */
    private function __construct(public int $entryKey) {}

    public static function afterEntry(int $entryKey): self
    {
        return new self($entryKey);
    }
}
