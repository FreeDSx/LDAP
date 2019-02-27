<?php
# A simple script to modify the OpenLDAP LDIF data to work with AD so we are working with the same data set.

$data = file_get_contents(__DIR__.'/../openldap/ldif/data.ldif');
$ldif = explode("\n", $data);
foreach ($ldif as $i => $line) {
    if (preg_match('/^userPassword/', $line)) {
        $ldif[$i] = 'userAccountControl: 514';
    }
}
file_put_contents(__DIR__ . '/ldif/data.ldif', implode("\n", $ldif));

$data = file_get_contents(__DIR__.'/../openldap/ldif/data-group.ldif');
$ldif = explode("\n", $data);
foreach ($ldif as $i => $line) {
    if (preg_match('/^objectClass/', $line)) {
        $ldif[$i] = 'objectClass: group';
    }
}
file_put_contents(__DIR__ . '/ldif/data-group.ldif', implode("\n", $ldif));