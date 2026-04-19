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
use Tests\Performance\FreeDSx\Ldap\LoadTest\LoadTestCommand;

require __DIR__ . '/../../vendor/autoload.php';

require_once __DIR__ . '/../performance/Config.php';
require_once __DIR__ . '/../performance/WorkloadMix.php';
require_once __DIR__ . '/../performance/StatsCollector.php';
require_once __DIR__ . '/../performance/StatsSnapshot.php';
require_once __DIR__ . '/../performance/ServerManager.php';
require_once __DIR__ . '/../performance/Worker.php';
require_once __DIR__ . '/../performance/Report.php';
require_once __DIR__ . '/../performance/Driver.php';
require_once __DIR__ . '/../performance/LoadTestCommand.php';

$command = new LoadTestCommand();
$application = new Application('FreeDSx LDAP load test');
$application->add($command);
$application->setDefaultCommand((string) $command->getName(), true);
$application->run();
