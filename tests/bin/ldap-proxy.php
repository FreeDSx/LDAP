<?php

declare(strict_types=1);

use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;

require __DIR__ . '/../../vendor/autoload.php';

$server = LdapServer::makeProxy(
    servers: 'localhost',
    serverOptions: (new ServerOptions())
        ->setPort(10389)
        ->setSocketAcceptTimeout(0.1)
        ->setOnServerReady(fn () => fwrite(STDOUT, 'server starting...' . PHP_EOL)),
);

$server->run();
