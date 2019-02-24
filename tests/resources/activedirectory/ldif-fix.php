<?php
# A simple script to modify the OpenLDAP LDIF data to work with AD so we are working with the same data set.

# A simple script to modify the OpenLDAP LDIF data to work with AD so we are working with the same data set.
# Unfortunately it is quite slow due to all the array_splice calls. Only needs to be run if the LDIF data changes.
$data = file_get_contents(__DIR__.'/../openldap/ldif/data.ldif');
$ldif = explode("\n", $data);
foreach ($ldif as $i => $line) {
    if (preg_match('/objectClass: inetOrgPerson/', $line)) {
        $ldif[$i] = 'objectClass: User';
    } elseif (preg_match('/^userPassword/', $line)) {
        $ldif[$i] = 'userAccountControl: 514';
    } elseif (preg_match('/^secretary/', $line)) {
        unset($ldif[$i]);
    }
}

$uids = [];
$offset = 0;
$ldif = array_values($ldif);
$i = 0;
foreach ($ldif as $i => $line) {
    if (preg_match('/^uid: (.*)/', $line, $matches)) {
        $uid = $matches[1];
        if (in_array($uid, $uids)) {
            $i++;
            $uid .= $i;
        } else {
            $uids[] = $uid;
        }
        \array_splice($ldif, ($i + $offset), 0, "sAMAccountName: $uid");
        $offset++;
        \array_splice($ldif, ($i + $offset), 0, "userPrincipalName: $uid@example.com");
        $offset++;
    }
}
file_put_contents(__DIR__ . '/ldif/data.ldif', implode("\n", $ldif));