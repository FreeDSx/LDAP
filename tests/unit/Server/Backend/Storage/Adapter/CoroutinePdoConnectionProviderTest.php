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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\CoroutinePdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoTxState;
use PDO;
use PHPUnit\Framework\TestCase;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;

final class CoroutinePdoConnectionProviderTest extends TestCase
{
    protected function setUp(): void
    {
        if (!extension_loaded('swoole')) {
            $this->markTestSkipped('The swoole extension is required for this test.');
        }
    }

    public function test_throws_when_called_outside_a_coroutine(): void
    {
        $provider = new CoroutinePdoConnectionProvider(
            fn (): PDO => $this->newPdo(),
        );

        $this->expectException(RuntimeException::class);
        $provider->get();
    }

    public function test_txState_throws_when_called_outside_a_coroutine(): void
    {
        $provider = new CoroutinePdoConnectionProvider(
            fn (): PDO => $this->newPdo(),
        );

        $this->expectException(RuntimeException::class);
        $provider->txState();
    }

    public function test_returns_same_pdo_on_repeat_calls_within_same_coroutine(): void
    {
        $provider = new CoroutinePdoConnectionProvider(
            fn (): PDO => $this->newPdo(),
        );

        $captured = [];

        Coroutine\run(function () use ($provider, &$captured): void {
            $first = $provider->get();
            $second = $provider->get();
            $captured['same'] = $first === $second;
            $captured['txStateSame'] = $provider->txState() === $provider->txState();
        });

        self::assertTrue($captured['same']);
        self::assertTrue($captured['txStateSame']);
    }

    public function test_returns_distinct_pdos_for_distinct_coroutines(): void
    {
        $factoryCount = 0;
        $provider = new CoroutinePdoConnectionProvider(
            function () use (&$factoryCount): PDO {
                $factoryCount++;

                return $this->newPdo();
            },
        );

        /** @var array<int, PDO> $pdos */
        $pdos = [];
        /** @var array<int, PdoTxState> $txStates */
        $txStates = [];

        Coroutine\run(function () use ($provider, &$pdos, &$txStates): void {
            $pdoCh = new Channel(2);
            $txCh = new Channel(2);
            $release = new Channel(2);

            Coroutine::create(function () use ($provider, $pdoCh, $txCh, $release): void {
                $pdoCh->push($provider->get());
                $txCh->push($provider->txState());
                $release->pop();
            });
            Coroutine::create(function () use ($provider, $pdoCh, $txCh, $release): void {
                $pdoCh->push($provider->get());
                $txCh->push($provider->txState());
                $release->pop();
            });

            for ($i = 0; $i < 2; $i++) {
                $pdo = $pdoCh->pop();
                self::assertInstanceOf(
                    PDO::class,
                    $pdo,
                );
                $pdos[] = $pdo;

                $tx = $txCh->pop();
                self::assertInstanceOf(
                    PdoTxState::class,
                    $tx,
                );
                $txStates[] = $tx;
            }

            $release->push(1);
            $release->push(1);
        });

        self::assertNotSame(
            $pdos[0],
            $pdos[1],
        );
        self::assertNotSame(
            $txStates[0],
            $txStates[1],
        );
        self::assertSame(
            2,
            $factoryCount,
        );
    }

    public function test_tx_state_depth_is_isolated_per_coroutine(): void
    {
        $provider = new CoroutinePdoConnectionProvider(
            fn (): PDO => $this->newPdo(),
        );

        $depths = [];

        Coroutine\run(function () use ($provider, &$depths): void {
            Coroutine::create(function () use ($provider, &$depths): void {
                $provider->txState()->depth = 3;
                Coroutine::sleep(0.01);
                $depths['a'] = $provider->txState()->depth;
            });
            Coroutine::create(function () use ($provider, &$depths): void {
                $depths['b'] = $provider->txState()->depth;
            });
        });

        self::assertSame(
            3,
            $depths['a'],
        );
        self::assertSame(
            0,
            $depths['b'],
        );
    }

    public function test_connections_are_released_when_coroutine_exits(): void
    {
        $created = 0;

        $provider = new CoroutinePdoConnectionProvider(
            function () use (&$created): PDO {
                $created++;

                return $this->newPdo();
            },
        );

        Coroutine\run(function () use ($provider): void {
            Coroutine::create(function () use ($provider): void {
                $provider->get();
            });
            Coroutine::create(function () use ($provider): void {
                $provider->get();
            });
        });

        Coroutine\run(function () use ($provider): void {
            $provider->get();
        });

        self::assertSame(
            3,
            $created,
        );

        $reflection = new \ReflectionClass($provider);
        $connectionsProp = $reflection->getProperty('connections');
        $txStatesProp = $reflection->getProperty('txStates');

        self::assertSame(
            [],
            $connectionsProp->getValue($provider),
        );
        self::assertSame(
            [],
            $txStatesProp->getValue($provider),
        );
    }

    private function newPdo(): PDO
    {
        return new PDO(
            'sqlite::memory:',
            null,
            null,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );
    }
}
