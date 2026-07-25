<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ProxyServerOptions;
use PHPUnit\Framework\TestCase;

final class ProxyOptionsTest extends TestCase
{
    public function test_it_exposes_the_server_options(): void
    {
        $serverOptions = new ProxyServerOptions();

        self::assertSame(
            $serverOptions,
            (new ProxyOptions($serverOptions))->getServerOptions(),
        );
    }

    public function test_it_exposes_the_client_options(): void
    {
        $clientOptions = new ClientOptions(['127.0.0.1']);

        self::assertSame(
            $clientOptions,
            (new ProxyOptions(new ProxyServerOptions(), $clientOptions))->getClientOptions(),
        );
    }

    public function test_it_does_not_use_start_tls_by_default(): void
    {
        self::assertFalse((new ProxyOptions(new ProxyServerOptions()))->getUseStartTls());
    }

    public function test_it_can_enable_upstream_start_tls(): void
    {
        self::assertTrue(
            (new ProxyOptions(new ProxyServerOptions()))->setUseStartTls(true)->getUseStartTls(),
        );
    }
}
