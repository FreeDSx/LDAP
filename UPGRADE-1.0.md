Upgrading from 0.x to 1.0
=======================

Client Options
--------------

When instantiating the `LdapClient`, options are now an options object instead of an associative array.

**Before**:

```php
use FreeDSx\Ldap\LdapClient;

$ldap = new LdapClient([
    # Servers are tried in order until one connects
    'servers' => ['dc1', 'dc2'],
    # The base_dn is used as the default for searches
    'base_dn' => 'dc=example,dc=local'
]);
```

**After**:

```php
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\ClientOptions;

$ldap = new LdapClient(
    (new ClientOptions)
        # Servers are tried in order until one connects
        ->setServers(['dc1', 'dc2'])
        # The base_dn is used as the default for searches
        ->setBaseDn('dc=example,dc=local')
);
```

Server Options
--------------

When instantiating the `LdapServer`, options are now an options object instead of an associative array.

**Before**:

```php
use FreeDSx\Ldap\LdapServer;

$ldap = new LdapServer([
    'dse_alt_server' => 'dc2.local',
    'port' => 33389,
]);
```

**After**:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;

$ldap = new LdapServer(
    (new ServerOptions)
        ->setDseAltServer('dc2.local')
        ->setPort(33389)
);
```
