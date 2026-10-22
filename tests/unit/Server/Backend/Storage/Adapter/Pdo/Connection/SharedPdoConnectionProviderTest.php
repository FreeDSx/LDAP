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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use PDO;
use PHPUnit\Framework\TestCase;

final class SharedPdoConnectionProviderTest extends TestCase
{
    private PDO $first;

    private PDO $second;

    private SharedPdoConnectionProvider $subject;

    protected function setUp(): void
    {
        $this->first = new PDO('sqlite::memory:');
        $this->second = new PDO('sqlite::memory:');
        $this->subject = new SharedPdoConnectionProvider(
            $this->first,
            fn(): PDO => $this->second,
        );
    }

    public function test_the_connection_is_kept_until_it_is_discarded(): void
    {
        $this->subject->get();

        self::assertSame(
            $this->first,
            $this->subject->get(),
        );
    }

    public function test_a_discarded_connection_is_replaced_on_its_next_use(): void
    {
        $this->subject->get();
        $this->subject->discard();

        self::assertSame(
            $this->second,
            $this->subject->get(),
        );
    }

    public function test_a_discarded_connection_is_kept_until_the_transaction_open_on_it_ends(): void
    {
        $this->subject->txState()->depth = 1;
        $this->subject->discard();

        self::assertSame(
            $this->first,
            $this->subject->get(),
        );

        $this->subject->txState()->depth = 0;

        self::assertSame(
            $this->second,
            $this->subject->get(),
        );
    }

    public function test_replacing_a_discarded_connection_releases_it_and_starts_a_fresh_transaction_state(): void
    {
        $released = [];
        $this->subject->onConnectionReleased(static function (PDO $pdo) use (&$released): void {
            $released[] = $pdo;
        });

        $this->subject->discard();
        $this->subject->get();

        self::assertSame(
            [$this->first],
            $released,
        );
        self::assertFalse($this->subject->txState()->lost);
    }
}
