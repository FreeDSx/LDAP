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

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTxState;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\RoutingPdoConnectionProvider;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteScope;
use PDO;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

final class RoutingPdoConnectionProviderTest extends TestCase
{
    use RequiresExtensionsTrait;

    private PdoConnectionProviderInterface&MockObject $reads;

    private PdoConnectionProviderInterface&MockObject $writes;

    private WriteScope $scope;

    private RoutingPdoConnectionProvider $subject;

    protected function setUp(): void
    {
        $this->reads = $this->createMock(PdoConnectionProviderInterface::class);
        $this->writes = $this->createMock(PdoConnectionProviderInterface::class);
        $this->scope = new WriteScope();

        $this->subject = new RoutingPdoConnectionProvider(
            $this->reads,
            $this->writes,
            $this->scope,
        );
    }

    public function test_a_caller_outside_the_writer_gets_the_reads_connection(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $this->reads
            ->method('get')
            ->willReturn($pdo);
        $this->writes
            ->expects(self::never())
            ->method('get');

        self::assertSame(
            $pdo,
            $this->subject->get(),
        );
    }

    public function test_the_writer_gets_the_writes_connection(): void
    {
        $this->requireSwoole();

        $pdo = new PDO('sqlite::memory:');
        $this->writes
            ->method('get')
            ->willReturn($pdo);
        $this->reads
            ->expects(self::never())
            ->method('get');

        $this->scope->enter();
        try {
            $connection = $this->subject->get();
        } finally {
            $this->scope->leave();
        }

        self::assertSame(
            $pdo,
            $connection,
        );
    }

    public function test_the_transaction_state_follows_the_connection(): void
    {
        $this->requireSwoole();

        $state = new PdoTxState();
        $this->writes
            ->method('txState')
            ->willReturn($state);

        $this->scope->enter();
        try {
            $txState = $this->subject->txState();
        } finally {
            $this->scope->leave();
        }

        self::assertSame(
            $state,
            $txState,
        );
    }

    public function test_reset_resets_both_connections(): void
    {
        $this->reads
            ->expects(self::once())
            ->method('reset');
        $this->writes
            ->expects(self::once())
            ->method('reset');

        $this->subject->reset();
    }

    public function test_a_release_listener_hears_about_both_connections(): void
    {
        $listener = static function (PDO $pdo): void {};

        $this->reads
            ->expects(self::once())
            ->method('onConnectionReleased')
            ->with($listener);
        $this->writes
            ->expects(self::once())
            ->method('onConnectionReleased')
            ->with($listener);

        $this->subject->onConnectionReleased($listener);
    }
}
