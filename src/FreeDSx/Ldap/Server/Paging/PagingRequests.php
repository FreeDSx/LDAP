<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * Represents a collection of paging requests from a client.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PagingRequests
{
    /**
     * @var PagingRequest[]
     */
    private $requests;

    /**
     * @param PagingRequest[] $pagingRequests
     */
    public function __construct(array $pagingRequests = [])
    {
        $this->requests = $pagingRequests;
    }

    public function add(PagingRequest $request): void
    {
        if ($this->has($request->getNextCookie())) {
            throw new ProtocolException('A request with this cookie already exists.');
        }

        $this->requests[] = $request;
    }

    public function remove(PagingRequest $toRemove): void
    {
        foreach ($this->requests as $i => $pagingRequest) {
            if ($pagingRequest === $toRemove) {
                unset($this->requests[$i]);
            }
        }
    }

    public function findByNextCookie(string $cookie): PagingRequest
    {
        $request = $this->getByNextCookie($cookie);
        if (!$request) {
            throw new ProtocolException('The supplied cookie is invalid.');
        }

        return $request;
    }

    public function has(string $cookie): bool
    {
        return (bool)$this->getByNextCookie($cookie);
    }

    private function getByNextCookie(string $cookie): ?PagingRequest
    {
        foreach ($this->requests as $pagingRequest) {
            if ($pagingRequest->getNextCookie() === $cookie) {
                return $pagingRequest;
            }
        }

        return null;
    }
}
