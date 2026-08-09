<?php

declare(strict_types=1);

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapProxyServer;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ProxyServerOptions;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use Symfony\Component\Process\Process;
use Tests\Support\FreeDSx\Ldap\TestWorker;

require __DIR__ . '/../../vendor/autoload.php';

$upstreamPort = TestWorker::port(TestWorker::OFFSET_UPSTREAM);

$upstream = new Process([
    'php',
    '-dpcov.enabled=0',
    __DIR__ . '/ldap-server.php',
    '--transport=ssl',
    '--port=' . $upstreamPort,
    '--entries=12',
]);
$upstream->start();

$deadline = microtime(true) + 10.0;
while ($upstream->isRunning()) {
    if (str_contains($upstream->getOutput(), 'server starting...')) {
        break;
    }
    if (microtime(true) >= $deadline) {
        break;
    }
    usleep(50_000);
}

register_shutdown_function(static fn() => $upstream->stop());

$server = new LdapProxyServer(new ProxyOptions(
    serverOptions: (new ProxyServerOptions((new NetworkConfig())
        ->setPort(TestWorker::port())
        ->setSslCert(__DIR__ . '/../resources/cert/slapd.crt')
        ->setSslCertKey(__DIR__ . '/../resources/cert/slapd.key')
        ->setSocketAcceptTimeout(0.1)))
        ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL)),
    clientOptions: (new ClientOptions())
        ->setServers(['127.0.0.1'])
        ->setPort($upstreamPort)
        ->setUseSsl(true)
        ->setSslValidateCert(false)
        ->setSslAllowSelfSigned(true),
));

$server->run();
