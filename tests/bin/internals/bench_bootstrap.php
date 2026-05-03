<?php

declare(strict_types=1);

/**
 * Bootstrap shared by the bench bin scripts. Sets memory_limit and self-reexecs
 * the current PHP process with opcache + tracing JIT enabled so the benchmark
 * client runs in JIT mode by default.
 *
 * The spawned FreeDSx server gets the same JIT flags via ServerManager. Pass
 * --no-jit on the command line to disable JIT on both sides for an
 * interpreter-mode baseline.
 */

ini_set('memory_limit', '512M');

if (getenv('FREEDSX_BENCH_BOOTSTRAPPED') === '1') {
    return;
}

$rawArgv = $_SERVER['argv'] ?? [];
$argv = [];
if (is_array($rawArgv)) {
    foreach ($rawArgv as $rawArg) {
        if (is_string($rawArg)) {
            $argv[] = $rawArg;
        }
    }
}

if (in_array('--no-jit', $argv, true)) {
    return;
}

/**
 * In multi-driver mode the parent does no hot work — it only orchestrates child
 * workers (each spawned with JIT flags). Skipping the JIT re-exec here avoids a
 * segfault observed under JIT when Symfony's Process::stop() tears down the
 * parent-owned server after children exit.
 */
foreach ($argv as $i => $arg) {
    if ($arg === '--driver-processes' && isset($argv[$i + 1]) && (int) $argv[$i + 1] > 1) {
        return;
    }
    if (str_starts_with($arg, '--driver-processes=') && (int) substr($arg, 19) > 1) {
        return;
    }
}

$opcacheCli = (string) ini_get('opcache.enable_cli');
$opcacheJit = (string) ini_get('opcache.jit');
$jitActive = $opcacheCli === '1'
    && $opcacheJit !== ''
    && $opcacheJit !== 'disable'
    && $opcacheJit !== 'off'
    && $opcacheJit !== '0';

if ($jitActive) {
    return;
}

if (!function_exists('pcntl_exec')) {
    fwrite(
        STDERR,
        "warning: pcntl extension unavailable; bench client will run interpreted. Pass JIT -d flags manually for symmetric numbers.\n",
    );

    return;
}

$execArgs = [
    '-dopcache.enable_cli=1',
    '-dopcache.jit_buffer_size=128M',
    '-dopcache.jit=tracing',
    $argv[0],
    ...array_slice($argv, 1),
];

$envs = getenv();
$envs['FREEDSX_BENCH_BOOTSTRAPPED'] = '1';

pcntl_exec(
    PHP_BINARY,
    $execArgs,
    $envs,
);

fwrite(
    STDERR,
    "warning: pcntl_exec failed; bench client will run interpreted.\n",
);
