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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer;

use Closure;
use FreeDSx\Ldap\Exception\RuntimeException;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Throwable;

/**
 * Funnels write closures from many coroutines through a single writer coroutine.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SwooleWriterQueue implements WriterQueueInterface
{
    /**
     * @var Channel<array{Closure, Channel<mixed>}>|null
     */
    private ?Channel $jobs = null;

    private bool $started = false;

    public function __construct(private readonly int $capacity = 1024)
    {
    }

    /**
     * Submit a write closure and block the caller until the writer reports completion.
     *
     * @throws Throwable
     */
    public function run(Closure $job): void
    {
        $this->ensureStarted();

        $reply = new Channel(1);

        $this->jobs?->push([
            $job,
            $reply,
        ]);
        $result = $reply->pop();

        if ($result instanceof Throwable) {
            throw $result;
        }
    }

    private function ensureStarted(): void
    {
        if ($this->started) {
            return;
        }

        if (Coroutine::getCid() === -1) {
            throw new RuntimeException(
                self::class . ' can only be used inside a Swoole coroutine.',
            );
        }

        $this->jobs = new Channel($this->capacity);
        $this->started = true;
        $this->spawnWriter($this->jobs);
    }

    /**
     * @param Channel<array{Closure, Channel<mixed>}> $jobs
     */
    private function spawnWriter(Channel $jobs): void
    {
        Coroutine::create(static function () use ($jobs): void {
            while (true) {
                $job = $jobs->pop();
                if ($job === false) {
                    return;
                }

                [$closure, $reply] = $job;

                try {
                    $closure();
                    $reply->push(true);
                } catch (Throwable $e) {
                    $reply->push($e);
                }
            }
        });
    }
}
