<?php

declare(strict_types=1);

/**
 * Server bootstrap script for LdapBackendStorageTest and ldap-load-test.
 *
 * Accepts two forms:
 *
 *   Legacy positional: php ldap-backend-storage.php <transport> [file|sqlite|swoole]
 *     - `file`   -> JsonFileStorage (pcntl runner)
 *     - `sqlite` -> SqliteStorage   (pcntl runner)
 *     - `swoole` -> InMemoryStorage (swoole runner)
 *     - omitted  -> InMemoryStorage (pcntl runner)
 *
 *   Named: php ldap-backend-storage.php <transport> --storage=<memory|json|sqlite|mysql> --runner=<pcntl|swoole>
 *
 *     `mysql` reads connection details from the MYSQL_DSN / MYSQL_USER / MYSQL_PASSWORD env vars,
 *     defaulting to `mysql:host=127.0.0.1;port=3306;dbname=freedsx` / `root` / `root`.
 */

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\MysqlStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqliteStorage;
use FreeDSx\Ldap\ServerOptions;

require __DIR__ . '/../../vendor/autoload.php';

$passwordHash = '{SHA}' . base64_encode(sha1('12345', true));

$transport = $argv[1] ?? 'tcp';
$legacyHandler = null;
$storageOpt = null;
$runnerOpt = null;
$portOpt = null;
$seedEntriesOpt = 0;

for ($i = 2; isset($argv[$i]); $i++) {
    $arg = $argv[$i];

    if (str_starts_with($arg, '--storage=')) {
        $storageOpt = substr($arg, strlen('--storage='));
    } elseif (str_starts_with($arg, '--runner=')) {
        $runnerOpt = substr($arg, strlen('--runner='));
    } elseif (str_starts_with($arg, '--port=')) {
        $portOpt = (int) substr($arg, strlen('--port='));
    } elseif (str_starts_with($arg, '--seed-entries=')) {
        $seedEntriesOpt = (int) substr($arg, strlen('--seed-entries='));
    } elseif ($legacyHandler === null && !str_starts_with($arg, '--')) {
        $legacyHandler = $arg;
    }
}

if ($seedEntriesOpt < 0) {
    fwrite(STDERR, "Invalid --seed-entries value: {$seedEntriesOpt}. Must be zero or greater." . PHP_EOL);
    exit(2);
}

if ($storageOpt !== null || $runnerOpt !== null) {
    $storage = $storageOpt ?? 'memory';
    $runner = $runnerOpt ?? 'pcntl';
} else {
    [$storage, $runner] = match ($legacyHandler) {
        'file' => ['json', 'pcntl'],
        'sqlite' => ['sqlite', 'pcntl'],
        'swoole' => ['memory', 'swoole'],
        default => ['memory', 'pcntl'],
    };
}

if (!in_array($storage, ['memory', 'json', 'sqlite', 'mysql'], true)) {
    fwrite(STDERR, "Invalid --storage value: {$storage}. Expected one of: memory, json, sqlite, mysql." . PHP_EOL);
    exit(2);
}
if (!in_array($runner, ['pcntl', 'swoole'], true)) {
    fwrite(STDERR, "Invalid --runner value: {$runner}. Expected one of: pcntl, swoole." . PHP_EOL);
    exit(2);
}

$entries = [
    new Entry(
        new Dn('dc=foo,dc=bar'),
        new Attribute('dc', 'foo'),
        new Attribute('objectClass', 'domain'),
    ),
    new Entry(
        new Dn('cn=user,dc=foo,dc=bar'),
        new Attribute('cn', 'user'),
        new Attribute('objectClass', 'inetOrgPerson'),
        new Attribute('userPassword', $passwordHash),
    ),
    new Entry(
        new Dn('ou=people,dc=foo,dc=bar'),
        new Attribute('ou', 'people'),
        new Attribute('objectClass', 'organizationalUnit'),
    ),
    new Entry(
        new Dn('cn=alice,ou=people,dc=foo,dc=bar'),
        new Attribute('cn', 'alice'),
        new Attribute('objectClass', 'inetOrgPerson'),
        new Attribute('sn', 'Smith'),
        new Attribute('mail', 'alice@foo.bar'),
        new Attribute('uidNumber', '99'),
    ),
];

for ($i = 1; $i <= $seedEntriesOpt; $i++) {
    $entries[] = new Entry(
        new Dn("cn=seed-{$i},ou=people,dc=foo,dc=bar"),
        new Attribute('cn', "seed-{$i}"),
        new Attribute('objectClass', 'inetOrgPerson'),
        new Attribute('sn', 'Seeded'),
        new Attribute('mail', "seed-{$i}@foo.bar"),
        new Attribute('uidNumber', (string) (1000 + $i)),
    );
}

$server = new LdapServer(
    (new ServerOptions())
        ->setPort($portOpt ?? 10389)
        ->setTransport($transport)
        ->setSocketAcceptTimeout(0.1)
        ->setOnServerReady(fn () => fwrite(STDOUT, 'server starting...' . PHP_EOL))
);

if ($storage === 'memory') {
    $server->useStorage(new InMemoryStorage($entries));
} elseif ($storage === 'json') {
    $filePath = sys_get_temp_dir() . '/ldap_test_backend_storage.json';

    if (file_exists($filePath)) {
        unlink($filePath);
    }

    $adapter = $runner === 'swoole'
        ? JsonFileStorage::forSwoole($filePath)
        : JsonFileStorage::forPcntl($filePath);

    if ($runner === 'swoole') {
        Swoole\Coroutine\run(function () use ($adapter, $entries): void {
            foreach ($entries as $entry) {
                $adapter->store($entry);
            }
        });
    } else {
        foreach ($entries as $entry) {
            $adapter->store($entry);
        }
    }

    $server->useStorage($adapter);
} elseif ($storage === 'sqlite') {
    $dbPath = sys_get_temp_dir() . '/ldap_test_backend_storage.sqlite';

    foreach ([$dbPath, $dbPath . '-wal', $dbPath . '-shm'] as $path) {
        if (file_exists($path)) {
            unlink($path);
        }
    }

    $adapter = $runner === 'swoole'
        ? SqliteStorage::forSwoole($dbPath)
        : SqliteStorage::forPcntl($dbPath);

    if ($runner === 'swoole') {
        Swoole\Coroutine\run(function () use ($adapter, $entries): void {
            foreach ($entries as $entry) {
                $adapter->store($entry);
            }
        });
    } else {
        foreach ($entries as $entry) {
            $adapter->store($entry);
        }
    }

    $server->useStorage($adapter);
} else {
    $dsn = getenv('MYSQL_DSN') ?: 'mysql:host=127.0.0.1;port=3306;dbname=freedsx';
    $user = getenv('MYSQL_USER') ?: 'root';
    $password = getenv('MYSQL_PASSWORD') ?: 'root';

    // Start each run from a known-empty table.
    $cleanup = new PDO(
        $dsn,
        $user,
        $password,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
    );
    $cleanup->exec('DROP TABLE IF EXISTS entries');
    unset($cleanup);

    $adapter = $runner === 'swoole'
        ? MysqlStorage::forSwoole($dsn, $user, $password)
        : MysqlStorage::forPcntl($dsn, $user, $password);

    if ($runner === 'swoole') {
        Swoole\Coroutine\run(function () use ($adapter, $entries): void {
            foreach ($entries as $entry) {
                $adapter->store($entry);
            }
        });
    } else {
        foreach ($entries as $entry) {
            $adapter->store($entry);
        }
    }

    $server->useStorage($adapter);
}

if ($runner === 'swoole') {
    $server->useSwooleRunner();
}

$server->run();
