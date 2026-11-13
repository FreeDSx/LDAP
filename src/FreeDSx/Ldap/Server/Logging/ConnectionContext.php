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

namespace FreeDSx\Ldap\Server\Logging;

use FreeDSx\Socket\Socket;

/**
 * Per-connection context produced by a {@see ServerRunnerInterface} and merged into every event the connection emits.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ConnectionContext
{
    public function __construct(
        public ?int $pid = null,
        public ?int $connId = null,
        public ?string $remoteIp = null,
    ) {}

    /**
     * The context of the connection on a socket, with the client's address when it has one.
     */
    public static function forSocket(
        Socket $socket,
        ?int $pid = null,
        ?int $connId = null,
    ): self {
        return new self(
            pid: $pid,
            connId: $connId,
            remoteIp: $socket->getPeerAddress()?->getIp(),
        );
    }

    /**
     * @return array<string, int|string>
     */
    public function toLogContext(): array
    {
        return array_filter(
            [
                EventContext::PID => $this->pid,
                EventContext::CONN_ID => $this->connId,
                EventContext::REMOTE_IP => $this->remoteIp,
            ],
            static fn(mixed $value): bool => $value !== null,
        );
    }
}
