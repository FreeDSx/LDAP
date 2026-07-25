<?php

declare(strict_types=1);

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\ServerOptions;
use Symfony\Component\Process\Process;

require __DIR__ . '/../../vendor/autoload.php';

$upstream = new Process([
    'php',
    '-dpcov.enabled=0',
    __DIR__ . '/ldap-server.php',
    '--transport=ssl',
    '--port=10390',
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

$server = LdapServer::makeProxy(
    new ProxyOptions(
        (new ClientOptions())
            ->setServers(['127.0.0.1'])
            ->setPort(10390)
            ->setUseSsl(true)
            ->setSslValidateCert(false)
            ->setSslAllowSelfSigned(true),
    ),
    (new ServerOptions(network: (new NetworkConfig())
        ->setPort(10389)
        ->setSslCert(__DIR__ . '/../resources/cert/slapd.crt')
        ->setSslCertKey(__DIR__ . '/../resources/cert/slapd.key')
        ->setSocketAcceptTimeout(0.1)))
        ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL)),
);

$server->run();
