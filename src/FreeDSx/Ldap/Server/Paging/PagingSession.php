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

use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;

/**
 * An unfinished paged search, kept between pages as a fingerprint of its request and the place to resume from.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PagingSession
{
    public function __construct(
        private readonly string $fingerprint,
        private string $nextCookie,
        private PageCursor $cursor,
    ) {}

    public function fingerprint(): string
    {
        return $this->fingerprint;
    }

    /**
     * The cookie the client sends to resume the search.
     */
    public function nextCookie(): string
    {
        return $this->nextCookie;
    }

    /**
     * Where the next page starts.
     */
    public function cursor(): PageCursor
    {
        return $this->cursor;
    }

    /**
     * Moves past a filled page, to resume from its cursor under a new cookie.
     */
    public function advance(
        string $nextCookie,
        PageCursor $cursor,
    ): void {
        $this->nextCookie = $nextCookie;
        $this->cursor = $cursor;
    }
}
