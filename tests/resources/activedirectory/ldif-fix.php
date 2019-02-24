<?php
# A simple script to modify the OpenLDAP LDIF data to work with AD so we are working with the same data set.

$data = file_get_contents(__DIR__.'/../openldap/ldif/data.ldif');
$ldif = explode("\n", $data);

$uid = '';
foreach ($ldif as $i => $line) {
    if (preg_match('/^uid: (.*)/', $line, $matches)) {
        $uid = $matches[1];
    }
    if (preg_match('/^userPassword/', $line)) {
        $ldif[$i] = 'userAccountControl: 514';
    } elseif (preg_match('/^secretary/', $line)) {
        $ldif[$i] = 'sAMAccountName: '.$uid;
    }
}

file_put_contents(__DIR__ . '/ldif/data.ldif', implode("\n", $ldif));
