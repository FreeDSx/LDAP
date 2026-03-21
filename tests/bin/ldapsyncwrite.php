<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;

require __DIR__ . '/../../vendor/autoload.php';

$signalFile = $argv[1] ?? null;

if ($signalFile === null) {
    fwrite(STDERR, 'Usage: ldapsyncwrite.php <signal_file>' . PHP_EOL);

    exit(1);
}

$deadline = time() + 30;
while (!file_exists($signalFile) && time() < $deadline) {
    usleep(100_000);
    clearstatcache(true, $signalFile);
}

if (!file_exists($signalFile)) {
    fwrite(STDERR, 'Timed out waiting for signal file.' . PHP_EOL);

    exit(1);
}

$caCert = (string) getenv('LDAP_CA_CERT');

$options = (new ClientOptions())
    ->setServers([(string) getenv('LDAP_SERVER')])
    ->setBaseDn((string) getenv('LDAP_BASE_DN'))
    ->setSslCaCert(
        $caCert === ''
            ? __DIR__ . '/../resources/cert/ca.crt'
            : $caCert
    );

$client = new LdapClient($options);
$client->bind(
    (string) getenv('LDAP_USERNAME'),
    (string) getenv('LDAP_PASSWORD'),
);

$entry = new Entry('cn=Birgit Pankhurst,ou=Janitorial,ou=FreeDSx-Test,dc=example,dc=com');
$entry->set('description', 'sync-test-' . time());
$client->update($entry);
$client->unbind();

echo 'write-complete' . PHP_EOL;
