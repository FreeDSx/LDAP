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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\CoroutinePdoConnectionProvider;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

use function Swoole\Coroutine\run;

final class CoroutinePdoConnectionProviderTest extends TestCase
{
    use RequiresExtensionsTrait;

    private CoroutinePdoConnectionProvider $subject;

    protected function setUp(): void
    {
        $this->requireSwoole();

        $this->subject = new CoroutinePdoConnectionProvider(
            static fn(): PDO => new PDO('sqlite::memory:'),
        );
    }

    public function test_it_notifies_listeners_when_the_coroutine_ends(): void
    {
        $released = [];
        $this->subject->onConnectionReleased(static function (PDO $pdo) use (&$released): void {
            $released[] = $pdo;
        });

        $opened = null;
        run(function () use (&$opened, &$released): void {
            $opened = $this->subject->get();

            self::assertSame(
                [],
                $released,
                'The connection is still in use while the coroutine runs.',
            );
        });

        self::assertSame(
            [$opened],
            $released,
        );
    }

    public function test_it_notifies_nothing_when_no_connection_was_opened(): void
    {
        $released = [];
        $this->subject->onConnectionReleased(static function (PDO $pdo) use (&$released): void {
            $released[] = $pdo;
        });

        run(static fn() => null);

        self::assertSame(
            [],
            $released,
        );
    }
}
