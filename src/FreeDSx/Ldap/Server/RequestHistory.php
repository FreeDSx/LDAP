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

use FreeDSx\Ldap\Server\Paging\PagingRequests;
use Generator;

/**
 * Used to retain history regarding certain client request details.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RequestHistory
{
    private PagingRequests $pagingRequests;

    /**
     * Per-connection generator store for active paging sessions.
     * Keyed by the cookie that the client will send on the next request.
     *
     * @var array<string, Generator>
     */
    private array $pagingGenerators = [];

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

    /**
     * Store a generator for the given paging cookie (the cookie that will be
     * sent to the client and returned on the next page request).
     */
    public function storePagingGenerator(
        string $cookie,
        Generator $generator,
    ): void {
        $this->pagingGenerators[$cookie] = $generator;
    }

    /**
     * Retrieve the generator associated with the given cookie, or null if
     * the cookie is not found.
     */
    public function getPagingGenerator(string $cookie): ?Generator
    {
        return $this->pagingGenerators[$cookie] ?? null;
    }

    /**
     * Remove and discard the generator associated with the given cookie.
     */
    public function removePagingGenerator(string $cookie): void
    {
        unset($this->pagingGenerators[$cookie]);
    }
}
