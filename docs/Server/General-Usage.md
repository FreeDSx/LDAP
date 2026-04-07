General LDAP Server Usage
===================

* [Running the Server](#running-the-server)
* [Creating a Proxy Server](#creating-a-proxy-server)
* [Providing a Backend](#providing-a-backend)
  * [Read-Only Backend](#read-only-backend)
  * [Writable Backend](#writable-backend)
  * [Built-In Storage Adapters](#built-in-storage-adapters)
    * [InMemoryStorageAdapter](#inmemorystorageadapter)
    * [JsonFileStorageAdapter](#jsonfilestorageadapter)
  * [Proxy Backend](#proxy-backend)
  * [Custom Filter Evaluation](#custom-filter-evaluation)
* [Handling the RootDSE](#handling-the-rootdse)
* [StartTLS SSL Certificate Support](#starttls-ssl-certificate-support)
* [SASL Authentication](#sasl-authentication)
  * [PLAIN Mechanism](#plain-mechanism)
  * [Challenge-Based Mechanisms (CRAM-MD5, DIGEST-MD5, and SCRAM)](#challenge-based-mechanisms-cram-md5-digest-md5-and-scram)

The LdapServer class runs an LDAP server process that accepts client requests and sends back responses. It defaults to
using a forking method (PCNTL) for handling client connections, which is only available on Linux.

The server has no built-in entry persistence. You provide a backend that implements the storage and authentication
logic for your use case. See the [Providing a Backend](#providing-a-backend) section for details.

## Running The Server

In its simplest form you construct the server and call `run()`. Without a backend configured, the server accepts
connections but rejects all operations with `unwillingToPerform`.

```php
use FreeDSx\Ldap\LdapServer;

$server = (new LdapServer())->run();
```

## Creating a Proxy Server

The server can act as a transparent proxy to another LDAP server via `LdapServer::makeProxy()`:

```php
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = LdapServer::makeProxy(
    // The LDAP server to proxy connections to...
    servers: 'ldap.example.com',
    // Any additional LdapClient options for the proxy...
    clientOptions: new ClientOptions(),
    // Any additional LdapServer options. In this case, run over port 3389
    serverOptions: (new ServerOptions)->setPort(3389),
);

$server->run();
```

For a customisable proxy, extend `ProxyBackend` directly. See [Proxy Backend](#proxy-backend).

## Providing a Backend

A backend is a class implementing `LdapBackendInterface` (read-only) or `WritableLdapBackendInterface` (read + write).
It is registered with `LdapServer::useBackend()`:

```php
use FreeDSx\Ldap\LdapServer;

$server = (new LdapServer())->useBackend(new MyBackend());
$server->run();
```

The framework routes all client LDAP operations — search, bind, add, delete, modify, rename, compare — to the backend.
Paging is handled automatically: the framework stores a PHP Generator per connection and resumes it for each page
request. Your `search()` implementation simply yields entries.

### Read-Only Backend

`LdapBackendInterface` covers the three operations needed for a read-only server:

```php
namespace App;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use Generator;

class MyReadOnlyBackend implements LdapBackendInterface
{
    /**
     * Yield entries that are candidates for the search. The framework applies
     * FilterEvaluator as a final pass, so you may pre-filter for efficiency or
     * yield all entries in scope for simplicity.
     */
    public function search(SearchContext $context): Generator
    {
        // $context->baseDn   — Dn: the search base
        // $context->scope    — int: SearchRequest::SCOPE_BASE_OBJECT | SCOPE_SINGLE_LEVEL | SCOPE_WHOLE_SUBTREE
        // $context->filter   — FilterInterface: the requested LDAP filter
        // $context->attributes — Attribute[]: requested attributes (empty = all)
        // $context->typesOnly — bool: return only attribute names, not values

        yield Entry::fromArray('cn=Foo,dc=example,dc=com', ['cn' => 'Foo', 'sn' => 'Bar']);
        yield Entry::fromArray('cn=Bar,dc=example,dc=com', ['cn' => 'Bar', 'sn' => 'Baz']);
    }

    /**
     * Return a single entry by DN, or null if it does not exist.
     * Used for compare operations and internal lookups.
     */
    public function get(Dn $dn): ?Entry
    {
        // ...
        return null;
    }

    /**
     * Verify a plaintext password for a simple bind request.
     * Return true if the credentials are valid, false otherwise.
     */
    public function verifyPassword(Dn $dn, string $password): bool
    {
        return $dn->toString() === 'cn=admin,dc=example,dc=com'
            && $password === 'secret';
    }
}
```

### Writable Backend

`WritableLdapBackendInterface` extends `LdapBackendInterface` with write operations:

```php
namespace App;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use Generator;

class MyBackend implements WritableLdapBackendInterface
{
    public function search(SearchContext $context): Generator
    {
        // yield matching entries...
    }

    public function get(Dn $dn): ?Entry
    {
        // ...
    }

    public function verifyPassword(Dn $dn, string $password): bool
    {
        // ...
    }

    public function add(Entry $entry): void
    {
        // Persist the new entry. Throw OperationException(ENTRY_ALREADY_EXISTS) if it exists.
    }

    public function delete(Dn $dn): void
    {
        // Remove the entry. Throw OperationException(NOT_ALLOWED_ON_NON_LEAF) if it has children.
    }

    /**
     * @param Change[] $changes
     */
    public function update(Dn $dn, array $changes): void
    {
        // Apply attribute changes to the entry.
    }

    public function move(Dn $dn, Rdn $newRdn, bool $deleteOldRdn, ?Dn $newParent): void
    {
        // Rename or move the entry (ModifyDN operation).
    }
}
```

### Built-In Storage Adapters

Two adapters are included for common use cases.

#### InMemoryStorageAdapter

An in-memory, array-backed storage adapter. Suitable for:

- **Swoole**: all connections share the same process memory.
- **PCNTL** with pre-seeded, read-only data: data seeded before `run()` is inherited by all forked child processes.

**Note**: With PCNTL, write operations performed by one child process are not visible to other children.

```php
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Storage\Adapter\InMemoryStorageAdapter;

$passwordHash = '{SHA}' . base64_encode(sha1('secret', true));

$adapter = new InMemoryStorageAdapter(
    new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
    new Entry(
        new Dn('cn=admin,dc=example,dc=com'),
        new Attribute('cn', 'admin'),
        new Attribute('userPassword', $passwordHash),
    ),
);

$server = (new LdapServer())->useBackend($adapter);
$server->run();
```

Password verification supports `{SHA}` hashed values stored in the `userPassword` attribute, as well as plaintext
comparisons. No password scheme is set automatically — the hash format must be present in the stored value.

#### JsonFileStorageAdapter

A file-backed adapter that persists the directory as a JSON file. Safe for PCNTL (write operations are serialised with
`flock(LOCK_EX)` and the in-memory cache is invalidated via `filemtime` checks).

Use the named constructor that matches your server runner:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\JsonFileStorageAdapter;

// PCNTL runner — uses flock() to serialise writes across forked processes
$adapter = JsonFileStorageAdapter::forPcntl('/var/lib/myapp/ldap.json');

// Swoole runner — uses a coroutine Channel mutex and non-blocking file I/O
$adapter = JsonFileStorageAdapter::forSwoole('/var/lib/myapp/ldap.json');

$server = (new LdapServer())->useBackend($adapter);
$server->run();
```

JSON format:

```json
{
  "cn=admin,dc=example,dc=com": {
    "dn": "cn=admin,dc=example,dc=com",
    "attributes": {
      "cn": ["admin"],
      "userPassword": ["{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="]
    }
  }
}
```

### Proxy Backend

`ProxyBackend` implements `WritableLdapBackendInterface` by forwarding all operations to an upstream LDAP server.
Extend it to add custom logic:

```php
namespace App;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Server\RequestHandler\ProxyBackend;

class MyProxyBackend extends ProxyBackend
{
    public function __construct()
    {
        parent::__construct(
            (new ClientOptions)
                ->setServers(['dc1.domain.local', 'dc2.domain.local'])
                ->setBaseDn('dc=domain,dc=local')
        );
    }
}
```

```php
use FreeDSx\Ldap\LdapServer;
use App\MyProxyBackend;

$server = (new LdapServer())->useBackend(new MyProxyBackend());
$server->run();
```

### Custom Filter Evaluation

By default the framework applies a pure-PHP `FilterEvaluator` to entries yielded by `search()` as a correctness
guarantee. For backends that translate LDAP filters to a native query language (SQL, MongoDB, etc.) and return
pre-filtered results, you can replace the evaluator:

```php
use FreeDSx\Ldap\LdapServer;
use App\MyBackend;
use App\MySqlFilterEvaluator;

$server = (new LdapServer())
    ->useBackend(new MyBackend())
    ->useFilterEvaluator(new MySqlFilterEvaluator());

$server->run();
```

The custom evaluator must implement `FreeDSx\Ldap\Server\Storage\FilterEvaluatorInterface`:

```php
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Storage\FilterEvaluatorInterface;

class MySqlFilterEvaluator implements FilterEvaluatorInterface
{
    public function evaluate(Entry $entry, FilterInterface $filter): bool
    {
        // Custom matching logic (e.g. bitwise matching rules for AD compatibility).
        return true;
    }
}
```

## Handling the RootDSE

The server generates a default RootDSE from `ServerOptions` values (`setDseNamingContexts()`, `setDseVendorName()`,
etc.). For most deployments this is sufficient.

If you need full control — for example to proxy RootDSE requests to an upstream server, or to add custom attributes —
implement `RootDseHandlerInterface`. Your implementation receives the default-generated entry and returns a (possibly
modified) entry to send back to the client.

The simplest way to proxy RootDSE requests is `ProxyHandler`, which bundles `ProxyBackend` with `RootDseHandlerInterface`
in one class and is used by `LdapServer::makeProxy()` automatically.

For a custom handler:

```php
namespace App;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;

class MyRootDseHandler implements RootDseHandlerInterface
{
    public function rootDse(
        RequestContext $context,
        SearchRequest $request,
        Entry $rootDse,
    ): Entry {
        // Modify the default entry or return a completely custom one.
        $rootDse->set('namingContexts', 'dc=example,dc=com');

        return $rootDse;
    }
}
```

Register it with the server:

```php
use FreeDSx\Ldap\LdapServer;
use App\MyRootDseHandler;

$server = (new LdapServer())
    ->useBackend(new MyBackend())
    ->useRootDseHandler(new MyRootDseHandler());

$server->run();
```

If your backend class also implements `RootDseHandlerInterface`, you do not need to call `useRootDseHandler()` — the
framework detects and uses it automatically.

## SASL Authentication

The server supports SASL bind requests. SASL must be explicitly enabled by configuring the mechanisms you want to
support via `ServerOptions::setSaslMechanisms()`. The configured mechanisms are advertised to clients through the
`supportedSaslMechanisms` RootDSE attribute.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = (new LdapServer(
    (new ServerOptions)->setSaslMechanisms(
        ServerOptions::SASL_PLAIN,
        ServerOptions::SASL_CRAM_MD5,
        ServerOptions::SASL_SCRAM_SHA_256,
    )
))->useBackend(new MyBackend());
```

### PLAIN Mechanism

The `PLAIN` mechanism reuses your existing `LdapBackendInterface::verifyPassword()` method. When a client
authenticates with SASL PLAIN, the server extracts the username and password from the SASL credentials and calls
`verifyPassword()` exactly as it would for a simple bind.

**Note**: PLAIN transmits credentials in cleartext. Only enable it when the connection is protected by TLS (StartTLS
or `setUseSsl`).

### Challenge-Based Mechanisms (CRAM-MD5, DIGEST-MD5, and SCRAM)

`CRAM-MD5`, `DIGEST-MD5`, and the `SCRAM-*` family are challenge-response mechanisms. The server issues a challenge to
the client and verifies the client's response against a digest computed from the user's plaintext password. Because the
verification is cryptographic, the server must be able to look up the plaintext (or equivalent) password for a given
username.

To support these mechanisms, your backend must additionally implement
`FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface`:

```php
interface SaslHandlerInterface
{
    public function getPassword(
        string $username,
        string $mechanism,
    ): ?string;
}
```

Return the user's plaintext password for the given username and mechanism, or `null` if the user does not exist or
should not be permitted to authenticate. Returning `null` results in a generic `invalidCredentials` error.

The `$mechanism` parameter lets you apply per-mechanism policy if needed (e.g. disallow weak mechanisms for certain
users), but in most cases you can ignore it and return the same password regardless.

Example backend supporting both simple binds and challenge-based SASL:

```php
namespace App;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;
use Generator;

class MyBackend implements LdapBackendInterface, SaslHandlerInterface
{
    private array $users = [
        'alice' => 'her-plaintext-password',
        'bob'   => 'his-plaintext-password',
    ];

    public function search(SearchContext $context): Generator
    {
        // yield entries...
    }

    public function get(Dn $dn): ?Entry
    {
        return null;
    }

    // Used for simple binds and SASL PLAIN.
    public function verifyPassword(Dn $dn, string $password): bool
    {
        $user = $this->users[$dn->toString()] ?? null;

        return $user !== null && $user === $password;
    }

    // Used for CRAM-MD5, DIGEST-MD5, and all SCRAM variants.
    public function getPassword(string $username, string $mechanism): ?string
    {
        return $this->users[$username] ?? null;
    }
}
```

Then enable the desired mechanisms on the server:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use App\MyBackend;

$server = (new LdapServer(
    (new ServerOptions)->setSaslMechanisms(
        ServerOptions::SASL_CRAM_MD5,
        ServerOptions::SASL_DIGEST_MD5,
        ServerOptions::SASL_SCRAM_SHA_256,
    )
))->useBackend(new MyBackend());

$server->run();
```

**SCRAM variants**: The following constants are available for the SCRAM family. `SCRAM-SHA-256` is the recommended
choice for new deployments ([RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) standardises it as the preferred
mechanism, citing SHA-1's known weaknesses).

| Constant                             | Mechanism                       |
|--------------------------------------|---------------------------------|
| `ServerOptions::SASL_SCRAM_SHA_1`    | `SCRAM-SHA-1`                   |
| `ServerOptions::SASL_SCRAM_SHA_256`  | `SCRAM-SHA-256` *(recommended)* |
| `ServerOptions::SASL_SCRAM_SHA_384`  | `SCRAM-SHA-384`                 |
| `ServerOptions::SASL_SCRAM_SHA_512`  | `SCRAM-SHA-512`                 |
| `ServerOptions::SASL_SCRAM_SHA3_512` | `SCRAM-SHA3-512`                |

Channel-binding (`-PLUS`) variants of each are also available (e.g. `SASL_SCRAM_SHA_256_PLUS`) for environments where
TLS channel binding is required.

**Note**: Because `getPassword()` must return the plaintext password, you cannot store passwords as one-way hashes
(e.g. bcrypt) when supporting CRAM-MD5, DIGEST-MD5, or SCRAM. If one-way hashing is a requirement, use `PLAIN` over
TLS instead, which allows password verification via `verifyPassword()`.

## StartTLS SSL Certificate Support

To allow clients to issue a StartTLS command against the LDAP server you need to provide an SSL certificate, key, and
key passphrase/password (if needed) when constructing the server class. If these are not present then the StartTLS
request will not be supported.

Adding the generated certs and keys on construction:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$options = (new ServerOptions)
    # The key can also be bundled in this cert
    ->setSslCert('/path/to/cert.pem')
    # The key for the cert. Not needed if bundled above.
    ->setSslCertKey('/path/to/cert.key')
    # The password/passphrase to read the key (if required)
    ->setSslCertPassphrase('This-Is-My-Secret-Password');

$server = new LdapServer($options);

$server->run();
```
