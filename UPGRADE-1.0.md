Upgrading from 0.x to 1.0
=======================

* [Client Changes](#client-changes)
    * [Client Options](#client-options)
* [Server Changes](#server-changes)
    * [Server Options](#server-options)
    * [Constructing a Proxy Server](#constructing-a-proxy-server)
    * [Using a Custom ServerRunner](#using-a-custom-serverrunner)
    * [Migrating from RequestHandlerInterface to LdapBackendInterface](#migrating-from-requesthandlerinterface-to-ldapbackendinterface)

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

## Migrating from RequestHandlerInterface to LdapBackendInterface

`RequestHandlerInterface`, `GenericRequestHandler`, `PagingHandlerInterface`, and related classes have been removed.
The server now works with a single backend object that implements `LdapBackendInterface` (read-only) or
`WritableLdapBackendInterface` (read-write). Paging is handled automatically by the framework via PHP generators —
no separate paging handler is needed.

**Before** (0.x `RequestHandlerInterface`):

```php
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;

class MyHandler extends GenericRequestHandler
{
    public function bind(
        RequestContext $context,
        string $username,
        string $password,
    ): bool {
        return $username === 'admin' && $password === 'secret';
    }

    public function search(
        RequestContext $context,
        SearchRequest $request,
    ): Entries {
        return new Entries();
    }
}

$server = new LdapServer(
    (new ServerOptions)
        ->setRequestHandler(new MyHandler())
);
```

**After** (1.0 `LdapBackendInterface`):

```php
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use Generator;

class MyBackend implements LdapBackendInterface
{
    public function search(SearchContext $context): Generator
    {
        // Yield matching entries. The framework handles paging automatically.
        yield from [];
    }

    public function get(Dn $dn): ?Entry
    {
        return null;
    }

    public function verifyPassword(
        Dn $dn,
        string $password,
    ): bool {
        return $dn->toString() === 'cn=admin,dc=example,dc=com'
            && $password === 'secret';
    }
}

$server = (new LdapServer())
    ->useBackend(new MyBackend());
```

### Write operations

`add()`, `delete()`, `update()`, and `move()` are now part of `WritableLdapBackendInterface`. Implement that interface
instead of `LdapBackendInterface` when your backend supports write operations.

### Paging

Paging no longer requires a `PagingHandlerInterface` implementation. Return a `Generator` from `search()` and the
framework automatically slices it into pages when a client sends a paged search control. The `supportedControl`
attribute of the RootDSE is populated automatically when a backend is configured.

### Proxy server

`ProxyRequestHandler` has been replaced by `ProxyBackend`. Extend it and provide an `LdapClient` instance:

```php
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\RequestHandler\ProxyBackend;

$server = (new LdapServer())
    ->useBackend(new ProxyBackend(
        (new ClientOptions)->setServers(['ldap.example.com'])
    ));
```

Or use the convenience factory (unchanged from 0.x):

```php
$server = LdapServer::makeProxy('ldap.example.com');
```
