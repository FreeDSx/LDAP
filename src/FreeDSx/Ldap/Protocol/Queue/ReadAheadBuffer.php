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

namespace FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Ldap\Protocol\LdapMessageRequest;

use function array_shift;
use function array_unshift;
use function count;

/**
 * The requests a connection read ahead of its dispatcher.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ReadAheadBuffer
{
    /**
     * Well above what a pipelining client sends mid-stream, but low enough to bound what one connection can buffer.
     */
    private const MAX_MESSAGES = 128;

    /**
     * Bounds what read-ahead holds by size, as a few large requests decode into far more memory than many small ones.
     */
    private const MAX_BYTES = 65_536;

    /**
     * @var LdapMessageRequest[]
     */
    private array $messages = [];

    /**
     * The bytes of the messages read ahead, counted until the buffer next empties.
     */
    private int $bytes = 0;

    /**
     * Puts a message at the front, so it is taken next.
     */
    public function prepend(LdapMessageRequest $message): void
    {
        array_unshift(
            $this->messages,
            $message,
        );
    }

    /**
     * Puts a message behind the ones already held, counting the bytes it was read from.
     */
    public function append(
        LdapMessageRequest $message,
        int $bytes = 0,
    ): void {
        $this->messages[] = $message;
        $this->bytes += $bytes;
    }

    /**
     * Takes the oldest message, or null when none is held.
     */
    public function take(): ?LdapMessageRequest
    {
        $message = array_shift($this->messages);
        // The bytes are counted for the buffer as a whole, so they are only forgotten once it empties.
        if ($this->messages === []) {
            $this->bytes = 0;
        }

        return $message;
    }

    /**
     * Whether the buffer holds as many messages, or as many bytes of them, as read-ahead may.
     */
    public function isFull(): bool
    {
        return count($this->messages) >= self::MAX_MESSAGES
            || $this->bytes >= self::MAX_BYTES;
    }
}
