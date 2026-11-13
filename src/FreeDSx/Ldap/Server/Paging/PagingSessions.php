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

use FreeDSx\Ldap\Exception\ProtocolException;

/**
 * The paged searches a client has left unfinished, held in the order they started.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class PagingSessions
{
    /**
     * @var PagingSession[]
     */
    private array $sessions = [];

    /**
     * @throws ProtocolException
     */
    public function add(PagingSession $session): void
    {
        if ($this->has($session->nextCookie())) {
            throw new ProtocolException('A session with this cookie already exists.');
        }

        $this->sessions[] = $session;
    }

    public function count(): int
    {
        return count($this->sessions);
    }

    /**
     * Discards the least recently started session once the limit is reached, reporting whether one was discarded.
     */
    public function evictOldestAtLimit(int $limit): bool
    {
        $oldest = array_key_first($this->sessions);

        if ($oldest === null || $limit <= 0 || $this->count() < $limit) {
            return false;
        }
        unset($this->sessions[$oldest]);

        return true;
    }

    public function remove(PagingSession $toRemove): void
    {
        foreach ($this->sessions as $i => $session) {
            if ($session === $toRemove) {
                unset($this->sessions[$i]);
            }
        }
    }

    /**
     * @throws ProtocolException
     */
    public function findByNextCookie(string $cookie): PagingSession
    {
        $session = $this->getByNextCookie($cookie);
        if ($session === null) {
            throw new ProtocolException('The supplied cookie is invalid.');
        }

        return $session;
    }

    public function has(string $cookie): bool
    {
        return $this->getByNextCookie($cookie) !== null;
    }

    private function getByNextCookie(string $cookie): ?PagingSession
    {
        foreach ($this->sessions as $session) {
            if ($session->nextCookie() === $cookie) {
                return $session;
            }
        }

        return null;
    }
}
