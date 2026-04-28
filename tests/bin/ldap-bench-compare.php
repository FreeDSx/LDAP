<?php

declare(strict_types=1);

/**
 * Side-by-side benchmark driver: runs the FreeDSx load test workload against an external LDAP
 * target and against a spawned FreeDSx server at identical parameters, then prints a comparison.
 *
 * Defaults point at a local OpenLDAP; override `--target-*` to aim at another server.
 *
 * Run with --help to see options.
 */

use Symfony\Component\Console\Application;
use Tests\Performance\FreeDSx\Ldap\Compare\BenchCompareCommand;

require __DIR__ . '/internals/bench_bootstrap.php';
require __DIR__ . '/../../vendor/autoload.php';

$command = new BenchCompareCommand();
$application = new Application('FreeDSx LDAP bench-compare');
$application->add($command);
$application->setDefaultCommand(
    (string) $command->getName(),
    true,
);
$application->run();
