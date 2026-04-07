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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock;

use FreeDSx\Ldap\Exception\RuntimeException;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;

/**
 * Locking strategy for the Swoole server runner.
 *
 * Uses a Swoole\Coroutine\Channel(1) as a coroutine-safe mutex.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class CoroutineLock implements StorageLockInterface
{
    /** @var Channel<mixed>|null */
    private ?Channel $mutex = null;

    public function __construct(private readonly string $filePath)
    {
    }

    public function withLock(callable $mutation): void
    {
        $mutex = $this->getOrCreateMutex();
        $mutex->pop();

        try {
            $result = $mutation($this->read());
            $this->write($result);
        } finally {
            $mutex->push(true);
        }
    }

    /** @return Channel<mixed> */
    private function getOrCreateMutex(): Channel
    {
        if ($this->mutex === null) {
            $this->mutex = self::createMutex();
        }

        return $this->mutex;
    }

    /** @return Channel<mixed> */
    private static function createMutex(): Channel
    {
        $mutex = new Channel(1);
        $mutex->push(true);

        return $mutex;
    }

    private function read(): string
    {
        $contents = Coroutine\System::readFile($this->filePath);

        return ($contents !== false) ? $contents : '';
    }

    private function write(string $contents): void
    {
        $result = Coroutine\System::writeFile(
            $this->filePath,
            $contents
        );

        if ($result === false) {
            throw new RuntimeException(sprintf(
                'Unable to write to storage file: %s',
                $this->filePath
            ));
        }
    }
}
