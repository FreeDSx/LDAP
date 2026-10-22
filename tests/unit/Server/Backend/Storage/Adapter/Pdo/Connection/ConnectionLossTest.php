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

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\ConnectionLoss;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\SharedPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\PdoErrorFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Pdo\DriverFailure;

final class ConnectionLossTest extends TestCase
{
    private PDO $first;

    private PDO $second;

    private SharedPdoConnectionProvider $provider;

    private ConnectionLoss $subject;

    protected function setUp(): void
    {
        $this->first = new PDO('sqlite::memory:');
        $this->second = new PDO('sqlite::memory:');
        $this->provider = new SharedPdoConnectionProvider(
            $this->first,
            fn(): PDO => $this->second,
        );
        $this->subject = new ConnectionLoss(
            $this->provider,
            new PdoErrorFactory(PdoDriver::Sqlite),
        );
    }

    public function test_a_lost_connection_is_answered_as_unavailable_and_replaced(): void
    {
        $lost = DriverFailure::of(
            10,
            'disk I/O error',
        );

        $translated = $this->subject->translate($lost);

        self::assertInstanceOf(
            StorageIoException::class,
            $translated,
        );
        self::assertSame(
            ResultCode::UNAVAILABLE,
            $translated->getCode(),
        );
        self::assertSame(
            $lost,
            $translated->getPrevious(),
        );
        self::assertSame(
            $this->second,
            $this->provider->get(),
        );
    }

    public function test_another_failure_is_returned_as_it_is_and_the_connection_kept(): void
    {
        $busy = DriverFailure::of(5);

        self::assertSame(
            $busy,
            $this->subject->translate($busy),
        );
        self::assertSame(
            $this->first,
            $this->provider->get(),
        );
    }
}
