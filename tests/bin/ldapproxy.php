<?php

declare(strict_types=1);

use FreeDSx\Ldap\LdapServer;

require __DIR__ . '/../../vendor/autoload.php';

$server = LdapServer::makeProxy(
    'localhost',
    [],
    ['port' => 3389]
);

echo "server starting..." . PHP_EOL;

$server->run();
