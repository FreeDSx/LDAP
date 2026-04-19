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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use Closure;
use FreeDSx\Ldap\Exception\RuntimeException;
use PDO;
use Swoole\Coroutine;

/**
 * Creates and caches a fresh PDO connection per Swoole coroutine.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class CoroutinePdoConnectionProvider implements PdoConnectionProviderInterface
{
    /**
     * @var array<int, PDO>
     */
    private array $connections = [];

    /**
     * @var array<int, PdoTxState>
     */
    private array $txStates = [];

    /**
     * @param Closure(): PDO $factory  Creates and fully initialises a fresh PDO each time it is invoked.
     */
    public function __construct(private readonly Closure $factory)
    {
    }

    public function get(): PDO
    {
        $cid = $this->requireCoroutineId();

        if (!isset($this->connections[$cid])) {
            $this->connections[$cid] = ($this->factory)();
            $this->txStates[$cid] = new PdoTxState();

            Coroutine::defer(function () use ($cid): void {
                unset(
                    $this->connections[$cid],
                    $this->txStates[$cid],
                );
            });
        }

        return $this->connections[$cid];
    }

    public function txState(): PdoTxState
    {
        $cid = $this->requireCoroutineId();

        if (!isset($this->txStates[$cid])) {
            $this->get();
        }

        return $this->txStates[$cid];
    }

    /**
     * No-op: connections are already isolated per coroutine, and coroutines do not cross fork boundaries.
     */
    public function reset(): void
    {
    }

    private function requireCoroutineId(): int
    {
        $cid = Coroutine::getCid();

        if ($cid === -1) {
            throw new RuntimeException(
                self::class . ' can only be used inside a Swoole coroutine.',
            );
        }

        return $cid;
    }
}
