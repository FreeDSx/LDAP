<?php

declare(strict_types=1);

/**
 * Server bootstrap script for LdapBackendStorageTest.
 */

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqliteStorage;
use FreeDSx\Ldap\ServerOptions;

require __DIR__ . '/../../vendor/autoload.php';

$passwordHash = '{SHA}' . base64_encode(sha1('12345', true));

$transport = $argv[1] ?? 'tcp';
$handler = $argv[2] ?? null;

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

$server = new LdapServer(
    (new ServerOptions())
        ->setPort(10389)
        ->setTransport($transport)
        ->setSocketAcceptTimeout(0.1)
        ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL))
);

if ($handler === 'file') {
    $filePath = sys_get_temp_dir() . '/ldap_test_backend_storage.json';

    if (file_exists($filePath)) {
        unlink($filePath);
    }

    $storage = JsonFileStorage::forPcntl($filePath);

    foreach ($entries as $entry) {
        $storage->store($entry);
    }

    $server->useStorage($storage);
} elseif ($handler === 'sqlite') {
    $dbPath = sys_get_temp_dir() . '/ldap_test_backend_storage.sqlite';

    foreach ([$dbPath, $dbPath . '-wal', $dbPath . '-shm'] as $path) {
        if (file_exists($path)) {
            unlink($path);
        }
    }

    $storage = SqliteStorage::forPcntl($dbPath);

    foreach ($entries as $entry) {
        $storage->store($entry);
    }

    $server->useStorage($storage);
} else {
    $server->useStorage(new InMemoryStorage($entries));
}

if ($handler === 'swoole') {
    $server->useSwooleRunner();
}

$server->run();
