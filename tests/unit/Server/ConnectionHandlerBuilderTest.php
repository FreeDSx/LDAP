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

namespace Tests\Unit\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Server\ConnectionHandlerBuilderInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Socket\Socket;
use PHPUnit\Framework\TestCase;

final class ConnectionHandlerBuilderTest extends TestCase
{
    public function test_it_builds_a_distinct_handler_per_connection(): void
    {
        $builder = $this->builderFor(new ServerOptions());

        self::assertNotSame(
            $builder->build($this->createMock(Socket::class)),
            $builder->build($this->createMock(Socket::class)),
        );
    }

    public function test_it_builds_a_handler_with_password_policy_enabled(): void
    {
        $this->expectNotToPerformAssertions();

        $options = (new ServerOptions())->setPasswordPolicy(new PasswordPolicy());
        $this->builderFor($options)->build($this->createMock(Socket::class));
    }

    public function test_it_builds_a_handler_with_sasl_mechanisms_configured(): void
    {
        $this->expectNotToPerformAssertions();

        $options = (new ServerOptions())->setSaslMechanisms(ServerOptions::SASL_PLAIN);
        $this->builderFor($options)->build($this->createMock(Socket::class));
    }

    private function builderFor(ServerOptions $options): ConnectionHandlerBuilderInterface
    {
        return Container::forServer($options)
            ->get(ConnectionHandlerBuilderInterface::class);
    }
}
