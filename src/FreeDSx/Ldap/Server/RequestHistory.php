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

use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Paging\PagingRequests;

/**
 * Used to retain history regarding certain client request details.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RequestHistory
{
    private PagingRequests $pagingRequests;

    /**
     * Where each active paging session left off, keyed by the cookie the client returns on its next request.
     *
     * A position rather than an open result, so nothing is held between requests but the place to resume from.
     *
     * @var array<string, PageCursor>
     */
    private array $pagingCursors = [];

    public function __construct(?PagingRequests $pagingRequests = null)
    {
        $this->pagingRequests = $pagingRequests ?? new PagingRequests();
    }

    /**
     * The currently active paging requests from the client.
     */
    public function pagingRequest(): PagingRequests
    {
        return $this->pagingRequests;
    }

    public function storePagingCursor(
        string $cookie,
        PageCursor $cursor,
    ): void {
        $this->pagingCursors[$cookie] = $cursor;
    }

    public function getPagingCursor(string $cookie): ?PageCursor
    {
        return $this->pagingCursors[$cookie] ?? null;
    }

    public function removePagingCursor(string $cookie): void
    {
        unset($this->pagingCursors[$cookie]);
    }
}
