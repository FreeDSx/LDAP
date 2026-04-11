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
`WritableLdapBackendInterface` (read-write). Paging is handled automatically by the backend via PHP generators —
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
        // Yield matching entries. Paging is handled automatically.
        yield from [];
    }

    public function get(Dn $dn): ?Entry
    {
        return null;
    }
}

$server = (new LdapServer())
    ->useBackend(new MyBackend());
```

### Authentication

The `bind()` method on `GenericRequestHandler` has been replaced by `PasswordAuthenticatableInterface`. Authentication
is now a separate concern decoupled from the backend.

**Default behaviour**: if your backend stores a `userPassword` attribute on entries, the built-in `PasswordAuthenticator`
verifies credentials automatically — no extra code needed. Supported schemes: `{SHA}`, `{SSHA}`, `{MD5}`, `{SMD5}`,
and plaintext.

**Custom authentication**: implement `PasswordAuthenticatableInterface` on your backend (or on a dedicated class) to
replicate the old `bind()` behaviour:

```php
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use Generator;
use SensitiveParameter;

class MyBackend implements LdapBackendInterface, PasswordAuthenticatableInterface
{
    public function search(SearchContext $context): Generator
    {
        yield from [];
    }

    public function get(Dn $dn): ?Entry
    {
        return null;
    }

    public function verifyPassword(
        string $name,
        #[SensitiveParameter] string $password,
    ): bool {
        return $name === 'cn=admin,dc=example,dc=com' && $password === 'secret';
    }

    public function getPassword(string $username, string $mechanism): ?string
    {
        // Return a plaintext password for challenge SASL mechanisms (CRAM-MD5, SCRAM-*, etc.),
        // or null to disable challenge SASL for this user.
        return null;
    }
}
```

The use of `PasswordAuthenticatableInterface` on the backend is automatically detected. Alternatively, register a
standalone authenticator:

```php
$server = (new LdapServer())
    ->useBackend(new MyBackend())
    ->usePasswordAuthenticator(new MyAuthenticator());
```

### Write operations

`add()`, `delete()`, `update()`, and `move()` are now part of `WritableLdapBackendInterface`. Each operation receives
a typed command object. Use `WritableBackendTrait` to implement the dispatch automatically:

```php
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WritableBackendTrait;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;

class MyBackend implements WritableLdapBackendInterface
{
    use WritableBackendTrait;

    // search() and get() as above ...

    public function add(AddCommand $command): void
    {
        // $command->entry — Entry to persist
    }

    public function delete(DeleteCommand $command): void
    {
        // $command->dn — Dn of the entry to remove
    }

    public function update(UpdateCommand $command): void
    {
        // $command->dn      — Dn of the entry to modify
        // $command->changes — Change[] of attribute changes
    }

    public function move(MoveCommand $command): void
    {
        // $command->dn           — current entry Dn
        // $command->newRdn       — new relative Dn
        // $command->deleteOldRdn — bool
        // $command->newParent    — ?Dn new parent
    }
}
```

Implement `WritableLdapBackendInterface` instead of `LdapBackendInterface` when your backend supports write operations.

### Paging

Paging no longer requires a `PagingHandlerInterface` implementation. Return a `Generator` from `search()` and the
the backend automatically slices it into pages when a client sends a paged search control. The `supportedControl`
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
