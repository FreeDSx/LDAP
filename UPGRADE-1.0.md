Upgrading from 0.x to 1.0
=======================

* [Client Changes](#client-changes)
    * [Client Options](#client-options)
* [Server Changes](#server-changes)
    * [Server Options](#server-options)
    * [Constructing a Proxy Server](#constructing-a-proxy-server)
    * [Using a Custom ServerRunner](#using-a-custom-serverrunner)

## Client Changes

### Client Options

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

# Server Changes

## Server Options

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

## Constructing a Proxy Server

When instantiating an `LdapServer` instance with `LdapServer::makeProxy()`, options are now an options object instead
of an associative array.

**Before**:

```php
use FreeDSx\Ldap\LdapServer;

$server = LdapServer::makeProxy(
    // The LDAP server to proxy connections to...
    'ldap.example.com',
    // Any additional LdapClient options for the proxy...
    [
         // Perhaps the server to proxy is on some non-standard port?
        'port' => 3389,
    ],
    // Any additional LdapServer options. In this case, also run this server over port 3389
    [
        'port' => 3389,
    ]
);
```

**After**:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ServerOptions;

$server = LdapServer::makeProxy(
    // The LDAP server to proxy connections to...
    'ldap.example.com',
    // Any additional LdapClient options for the proxy...
    (new ClientOptions)
        // Perhaps the server to proxy is on some non-standard port?
        ->setPort(3389)
    ,
    // Any additional LdapServer options. In this case, also run this server over port 3389
    (new ServerOptions)
        ->setPort(3389)
);
```

## Using a Custom ServerRunner

Previously, when constructing a `LdapServer` instance you could pass in a second param with an object implementing `ServerRunnerInterface`.
This is no longer a param on the constructor, you must set it in the ServerOptions.

**Before**:

```php
use FreeDSx\Ldap\LdapServer;
use App\MyServerRunner;

$ldap = new LdapServer(
    [],
    new MyServerRunner(),
);
```

**After**:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;

$ldap = new LdapServer(
    (new ServerOptions)
        ->setServerRunner(new MyServerRunner())
);
```
