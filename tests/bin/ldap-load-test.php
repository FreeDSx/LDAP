<?php

declare(strict_types=1);

/**
 * Load-test driver for the FreeDSx LDAP storage backends.
 *
 * Spawns an LDAP server with the chosen backend+runner, fires concurrent LDAP operations from a
 * Swoole coroutine pool, then prints per-op latency/throughput/error stats. Run with --help to
 * see the full option list.
 */

use Symfony\Component\Console\Application;
use Tests\Performance\FreeDSx\Ldap\LoadTestCommand;

require __DIR__ . '/internals/bench_bootstrap.php';
require __DIR__ . '/../../vendor/autoload.php';

$command = new LoadTestCommand();
$application = new Application('FreeDSx LDAP load test');
$application->add($command);
$application->setDefaultCommand(
    (string) $command->getName(),
    true,
);
$application->run();
