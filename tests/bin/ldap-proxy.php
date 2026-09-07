<?php

declare(strict_types=1);

use Symfony\Component\Console\Application;
use Tests\Support\FreeDSx\Ldap\LdapProxyCommand;

require __DIR__ . '/../../vendor/autoload.php';

$command = new LdapProxyCommand();
$app = new Application('LDAP test proxy');
$app->add($command);
$app->setDefaultCommand(
    (string) $command->getName(),
    true,
);
$app->run();
