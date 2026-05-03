<?php

declare(strict_types=1);

/**
 * Internal worker invoked by MultiDriverCoordinator. Reads a serialized Config from STDIN,
 * runs a single Driver, and writes a serialized StatsSnapshot to STDOUT. Progress + errors
 * go to STDERR so they don't corrupt the snapshot stream.
 *
 * Not for direct use — invoke ldap-bench-compare with --driver-processes=N instead.
 */

use Symfony\Component\Console\Output\ConsoleOutput;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Output\StreamOutput;
use Tests\Performance\FreeDSx\Ldap\Config;
use Tests\Performance\FreeDSx\Ldap\Driver;

require __DIR__ . '/bench_bootstrap.php';
require __DIR__ . '/../../../vendor/autoload.php';

$payload = stream_get_contents(STDIN);

if ($payload === false || $payload === '') {
    fwrite(STDERR, "bench-driver-worker: empty STDIN\n");

    exit(2);
}

$config = @unserialize($payload, [
    'allowed_classes' => [Config::class],
]);

if (!$config instanceof Config) {
    fwrite(STDERR, "bench-driver-worker: STDIN did not unserialize to a Config\n");

    exit(2);
}

if ($config->serverMode !== 'external') {
    fwrite(STDERR, "bench-driver-worker: child Config must use serverMode=external\n");

    exit(2);
}

try {
    $progress = makeStderrOutput();
    $snapshot = (new Driver($config))->run($progress);
} catch (Throwable $e) {
    fwrite(STDERR, sprintf(
        "bench-driver-worker: Driver failed: %s: %s\n%s\n",
        $e::class,
        $e->getMessage(),
        $e->getTraceAsString(),
    ));

    exit(1);
}

echo serialize($snapshot);

exit(0);

function makeStderrOutput(): OutputInterface
{
    $stderr = fopen('php://stderr', 'wb');

    if ($stderr === false) {
        return new ConsoleOutput();
    }

    return new StreamOutput($stderr);
}
