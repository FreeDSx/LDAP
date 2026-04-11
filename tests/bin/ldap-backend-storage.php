<?php

declare(strict_types=1);

/**
 * Server bootstrap script for LdapBackendStorageTest.
 */

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorageAdapter;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorageAdapter;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
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
    ),
];

if ($handler === 'file') {
    $filePath = sys_get_temp_dir() . '/ldap_test_backend_storage.json';

    if (file_exists($filePath)) {
        unlink($filePath);
    }

    $adapter = JsonFileStorageAdapter::forPcntl($filePath);

    foreach ($entries as $entry) {
        $adapter->add(new AddCommand($entry));
    }
} else {
    $adapter = new InMemoryStorageAdapter($entries);
}

$server = (new LdapServer(
    (new ServerOptions())
        ->setPort(10389)
        ->setTransport($transport)
        ->setOnServerReady(fn() => fwrite(STDOUT, 'server starting...' . PHP_EOL))
))->useBackend($adapter);

if ($handler === 'swoole') {
    $server->useSwooleRunner();
}

$server->run();
