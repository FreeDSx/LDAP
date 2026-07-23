General LDAP Server Usage
===================

* [Quick Start Scenarios](#quick-start-scenarios)
  * [In-Memory Server](#in-memory-server)
  * [File-Backed Server with Custom Bind Names](#file-backed-server-with-custom-bind-names)
  * [Challenge SASL with a Custom Authenticator](#challenge-sasl-with-a-custom-authenticator)
* [Running the Server](#running-the-server)
* [Reloading Configuration on SIGHUP](#reloading-configuration-on-sighup)
* [Creating a Proxy Server](#creating-a-proxy-server)
* [Providing a Backend](#providing-a-backend)
  * [Built-In Storage Implementations](#built-in-storage-implementations)
    * [InMemoryStorage](#inmemorystorage)
    * [JsonFileStorage](#jsonfilestorage)
    * [SQLite](#sqlite)
    * [MySQL](#mysql)
* [LDIF Data](#ldif-data)
  * [Seeding Initial Entries](#seeding-initial-entries)
  * [Replaying LDIF Changelogs](#replaying-ldif-changelogs)
  * [Dumping the Directory](#dumping-the-directory)
  * [Inspecting Parsed LDIF](#inspecting-parsed-ldif)
* [Authentication](#authentication)
  * [Default Authentication](#default-authentication)
  * [Custom Bind Name Resolution](#custom-bind-name-resolution)
  * [Custom Authenticator](#custom-authenticator)
* [Handling the RootDSE](#handling-the-rootdse)
* [StartTLS SSL Certificate Support](#starttls-ssl-certificate-support)
* [SASL Authentication](#sasl-authentication)
  * [PLAIN Mechanism](#plain-mechanism)
  * [Challenge-Based Mechanisms (CRAM-MD5, DIGEST-MD5, and SCRAM)](#challenge-based-mechanisms-cram-md5-digest-md5-and-scram)
  * [Identity Resolution for SASL](#identity-resolution-for-sasl)
* [Password Modify Extended Operation](#password-modify-extended-operation)

The LdapServer class runs an LDAP server process that accepts client requests and sends back responses. It defaults to
using a forking method (PCNTL) for handling client connections, which is only available on Linux.

> **⚠️ PCNTL runner and the JIT**
>
> Under the PCNTL runner with high server load, PHP's JIT has been observed to cause instability in forked workers
> (tracing JIT crashing, function JIT failing to serve). This appears related to current upstream JIT instability rather
> than a FreeDSx issue. If you hit it, try running with `opcache.jit=off`. The single-process Swoole runner has not shown
> this.

The server has no built-in entry persistence. You provide a backend that implements the storage logic for your use
case. Authentication is a separate, independently configurable concern. See [Providing a Backend](#providing-a-backend)
and [Authentication](#authentication) for details.

## Quick Start Scenarios

### In-Memory Server

The simplest useful setup: an in-memory directory pre-seeded with entries. Ideal for testing or applications that
reconstruct the directory on each start.

The built-in `PasswordAuthenticator` handles bind authentication automatically — it reads the `userPassword` attribute
from entries and verifies credentials against it. Supported hash schemes: `{SHA}`, `{SSHA}`, `{MD5}`, `{SMD5}`, and
plaintext.

```php
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\ServerOptions;

$passwordHash = '{SHA}' . base64_encode(sha1('secret', true));

$options = new ServerOptions(InMemoryStorageConfig::withEntries([
    new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
    new Entry(
        new Dn('cn=admin,dc=example,dc=com'),
        new Attribute('cn', 'admin'),
        new Attribute('userPassword', $passwordHash),
    ),
]));

$server = new LdapServer($options);
$server->run();
```

Clients bind as `cn=admin,dc=example,dc=com` with password `secret`. No further configuration needed.

---

### File-Backed Server with Custom Bind Names

A persistent directory stored in a JSON file. Clients bind with a bare username (`alice`) instead of a full DN.
The built-in identity resolver already handles this; if the bind name is not a valid DN, it falls back to
searching for an entry where the `uid` attribute matches.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Config\JsonStorageConfig;
use FreeDSx\Ldap\ServerOptions;

$options = (new ServerOptions())
    ->setSaslMechanisms(ServerOptions::SASL_PLAIN)
    ->setStorageConfig(JsonStorageConfig::forFile('/var/lib/myapp/ldap.json'));

$server = new LdapServer($options);
$server->run();
```

To use a different attribute (e.g. `mail`) or restrict the search base, configure `setIdentityResolver()` via
[configuration](Configuration.md#setidentityresolver).

---

### Challenge SASL with a Custom Authenticator

For full control over credential storage, such as delegating to an external user store or database, implement
`PasswordAuthenticatableInterface` directly. This single interface covers all bind types:

- `authenticate()` is called for simple binds
- `getSaslIdentity()` is called for all SASL mechanisms (PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM-*)

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Backend\Storage\Config\JsonStorageConfig;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

class MyAuthenticator implements PasswordAuthenticatableInterface
{
    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        // Verify against your user store — any hashing scheme works here.
    }

    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        // Challenge SASL requires a plaintext (or recoverable) password.
        // Passwords stored with one-way hashing (bcrypt, argon2) cannot be used here.
        $password = $this->lookupPlaintextPassword($username);
        $dn = $this->lookupDn($username);

        return $password !== null && $dn !== null
            ? new SaslIdentity($password, $dn)
            : null;
    }
}

$options = (new ServerOptions())
    ->setSaslMechanisms(
        ServerOptions::SASL_PLAIN,
        ServerOptions::SASL_SCRAM_SHA_256,
    )
    ->setStorageConfig(JsonStorageConfig::forFile('/var/lib/myapp/ldap.json'))
    ->setPasswordAuthenticator(new MyAuthenticator());

$server = new LdapServer($options);
$server->run();
```

The backend handles directory data (search, writes). The authenticator handles credentials. Neither needs to know
about the other.

---

## Running The Server

In its simplest form you construct the server and call `run()`. `ServerOptions` defaults to a transient in-memory
backend when no storage config is given. This default is for testing only. In production supply a persistent
backend config such as `PdoConfig::forSqlite()`.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(new ServerOptions());
$server->run();
```

## Reloading Configuration on SIGHUP

A running server can reload its configuration on a `SIGHUP` signal without dropping connections. New connections
accepted after the reload use the updated configuration. Connections already in flight keep the configuration they
started with. This works on both the PCNTL and Swoole runners.

By default `SIGHUP` is a logged no-op. To opt in, register a reloader via `ServerOptions::setConfigReloader()`. The
reloader is invoked on each `SIGHUP` and returns the `ServerOptions` the server should adopt going forward:

```php
use FreeDSx\Ldap\Server\Configuration\ConfigReloaderInterface;
use FreeDSx\Ldap\ServerOptions;

final class FileConfigReloader implements ConfigReloaderInterface
{
    public function __construct(private readonly string $configFile)
    {
    }

    public function reload(ServerOptions $current): ServerOptions
    {
        $config = json_decode((string) file_get_contents($this->configFile), true);

        // Clone the current options so the backend and other wiring carry forward,
        // then apply just the settings your config file controls.
        return (clone $current)
            ->setAllowAnonymous($config['allow_anonymous'] ?? false)
            ->setMaxSearchSize($config['max_search_size'] ?? 1000);
    }
}
```

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;

$options = (new ServerOptions())
    ->setStorageConfig($storageConfig)
    ->setConfigReloader(new FileConfigReloader('/etc/myapp/ldap.json'));

$server = new LdapServer($options);
$server->run();
```

Trigger a reload by sending a signal to the server process, e.g. `kill -HUP <pid>`.

**Cloning the current options** (`clone $current`) is the simplest way to write a reloader. It preserves the backend
and everything else already configured while you change only the settings you care about. Returning a brand-new
`ServerOptions` would drop that wiring.

**What reloads.** Anything resolved per connection:

* **Authorization:** access control rules and privileged controls
* **Schema and validation:** schema, validation mode, and password policy
* **Limits and logging:** search limits, logger, and event-log policy
* **Session and capabilities:** SASL mechanisms, RootDSE settings, and the authentication flags (require-authentication, allow-anonymous)

**What does not reload.** The listening socket is fixed once the server is running:

* Bind IP, port, transport, and unix socket path
* The choice of runner (PCNTL vs Swoole)
* A StartTLS certificate change applies to new connections only

**On failure:** if the reloader throws, the error is logged and the server keeps its current configuration. The bad
reload is discarded rather than taking the server down.

## Creating a Proxy Server

The server can act as a transparent proxy to an upstream LDAP server via `LdapServer::makeProxy()`.

**Note**: Each client connection gets its own upstream connection. Requests (with their controls) are relayed upstream and
the responses (with their controls) relayed back. So the upstream is the authority. Works on all server runners.

```php
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ProxyOptions;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

// The upstream connection: servers + TLS live on the ClientOptions.
$proxyOptions = new ProxyOptions(
    (new ClientOptions())
        ->setServers(['ldap.example.com'])
        // Upstream TLS: LDAPS here, or $proxyOptions->setUseStartTls(true) for StartTLS.
        ->setUseSsl(true),
);

// The proxy's own listener: port/transport + downstream TLS cert.
$serverOptions = (new ServerOptions())
    ->setPort(3389)
    ->setSslCert('/path/to/cert.pem')
    ->setSslCertKey('/path/to/key.pem');

$server = LdapServer::makeProxy(
    $proxyOptions,
    $serverOptions,
);
$server->run();
```

TLS terminates at each hop: configure the **upstream** hop on the `ClientOptions` (LDAPS via `setUseSsl`,
or `ProxyOptions::setUseStartTls(true)`), and the **downstream** hop on the `ServerOptions` (LDAPS, or a
client StartTLS upgrade using the configured server cert).

**Note**: only simple and anonymous binds are proxied (SASL is not), and every request is forwarded to the
single configured upstream.

## Providing a Backend

Configure backend storage via `setStorageConfig()` or pass a config to the `ServerOptions` constructor
(`new ServerOptions(StorageConfigInterface $config)`). Pick the config that matches your persistence needs: in-memory,
JSON file, PDO-SQLite, or PDO-MySQL. When no config is given the server uses a transient in-memory backend, which is
for testing only.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;

$server = new LdapServer(new ServerOptions(InMemoryStorageConfig::withEntries($entries)));
$server->run();
```

Each config is a value object. The container builds the runner-appropriate storage for the runner set on
`ServerOptions`, so the same config works under both the PCNTL and Swoole runners.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;

$server = new LdapServer(new ServerOptions(PdoConfig::forSqlite('/var/lib/myapp/ldap.sqlite')));
$server->run();
```

All client LDAP operations (search, add, delete, modify, rename, compare) are routed to the backend.
Paging is handled automatically: a PHP generator is stored per connection and resumes it for each page request.

Authentication is a separate concern handled by `PasswordAuthenticatableInterface`. See [Authentication](#authentication).

### Built-In Storage Implementations

Four storage backends are included, each selected via a config object passed to `setStorageConfig()`:

- **SQLite** (`PdoConfig::forSqlite()`): recommended for most deployments. It is the most optimized backend and gives durable persistence with concurrent access.
- **MySQL** (`PdoConfig::forMysql()`): durable persistence backed by a shared MySQL/MariaDB server.
- **JsonFileStorage** (`JsonStorageConfig::forFile()`): a single JSON file, useful for small directories.
- **InMemoryStorage** (`InMemoryStorageConfig::withEntries()`): non-persistent, ideal for testing or read-only PCNTL data seeded before `run()`.

#### InMemoryStorage

An in-memory, array-backed storage implementation. Suitable for:

- **Swoole**: all connections share the same process memory, so reads and writes are visible to every client.
- **PCNTL** with pre-seeded, read-only data: data seeded before `run()` is inherited by all forked child processes.

> **⚠️ PCNTL write caveat**
>
> Under the PCNTL runner, `InMemoryStorage` is **not safe for multi-client write workloads**. Each forked child receives
> its own copy of the store at fork time. Written data is not propagated.
>
> Use `JsonStorageConfig` or a SQLite/MySQL `PdoConfig` if you need write behavior under the PCNTL runner.

```php
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Config\InMemoryStorageConfig;
use FreeDSx\Ldap\ServerOptions;

$passwordHash = '{SHA}' . base64_encode(sha1('secret', true));

$options = new ServerOptions(InMemoryStorageConfig::withEntries([
    new Entry(new Dn('dc=example,dc=com'), new Attribute('dc', 'example')),
    new Entry(
        new Dn('cn=admin,dc=example,dc=com'),
        new Attribute('cn', 'admin'),
        new Attribute('userPassword', $passwordHash),
    ),
]));

$server = new LdapServer($options);
$server->run();
```

#### JsonFileStorage

A file-backed storage implementation that persists the directory as a JSON file. Safe for PCNTL (write operations are
serialised with `flock(LOCK_EX)` and the in-memory read cache is invalidated via `filemtime` checks).

Pass a `JsonStorageConfig::forFile()` to the `ServerOptions` constructor. The container selects the PCNTL
implementation (`flock()` serialised writes) or the Swoole implementation (coroutine Channel mutex, non-blocking file
I/O) to match the configured runner:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Config\JsonStorageConfig;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(new ServerOptions(JsonStorageConfig::forFile('/var/lib/myapp/ldap.json')));
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

#### SQLite

A SQLite-backed `PdoStorage` that persists the directory in a SQLite database file via PDO. Suitable for
use cases that need durable persistence across restarts with support for concurrent access:

- **PCNTL**: a single shared PDO connection is inherited by all forked child processes. SQLite WAL mode handles concurrent access at the OS level.
- **Swoole**: each coroutine gets its own PDO connection to avoid blocking.

Pass a `PdoConfig::forSqlite()` to the `ServerOptions` constructor. The container builds the shared-connection
(PCNTL) or per-coroutine (Swoole) storage to match the configured runner, both using WAL journal mode:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(new ServerOptions(PdoConfig::forSqlite('/var/lib/myapp/ldap.sqlite')));
$server->run();
```

Use `:memory:` as the path to run a non-persistent, in-process SQLite database (useful for testing):

```php
$server = new LdapServer(new ServerOptions(PdoConfig::forSqlite(':memory:')));
```

#### MySQL

A MySQL/MariaDB-backed `PdoStorage`. Requires MySQL 8.0+ or MariaDB 10.6+.

Pass a `PdoConfig::forMysql()` to the `ServerOptions` constructor. The container builds the shared-connection (PCNTL)
or per-coroutine (Swoole) storage to match the configured runner:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(new ServerOptions(
    PdoConfig::forMysql('mysql:host=localhost;dbname=ldap', 'user', 'secret'),
));
$server->run();
```

The DSN follows the standard PDO MySQL format. The character set is automatically configured to `utf8mb4`
and the time zone to UTC on each connection.

##### Custom PDO driver

`PdoConfig::forSqlite()` and `PdoConfig::forMysql()` are conveniences over the generic `PdoConfig::forDriver()`,
which builds a config for any PDO driver. Supply your `PdoDialectInterface`, the DSN, and the required PDO driver
extension, then tune the rest with the setters. Your dialect's `createFilterTranslator()` supplies the paired
`FilterTranslatorInterface` (with the substring index injected):

```php
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;

$config = PdoConfig::forDriver(
    new MyPostgresDialect(),
    'pgsql:host=localhost;dbname=ldap',
    'pdo_pgsql',
)
    ->setUsername('user')
    ->setPassword('secret')
    ->setSessionStatements(["SET client_encoding = 'UTF8'"]);
```

`PdoConfig` implements `StorageConfigInterface`, so pass `$config` to `setStorageConfig()` or the `ServerOptions`
constructor like any other backend config.

## LDIF Data

`seed()`, `applyChanges()`, and `dump()` all stream. LDIF input is always taken through `LdifLoaderInterface`
such as `FileLdifLoader` for a path, `StringLdifLoader` for an in-memory string, or your own implementation for any
other source (database, remote URL, gzip stream, etc.). LDIF output uses the parallel `LdifOutputInterface` such as 
`FileLdifOutput` and `StringLdifOutput`.

### Seeding Initial Entries

`LdapServer::seed()` bulk-imports RFC 2849 LDIF content records into the storage configured via
`ServerOptions::setStorageConfig()` in one atomic transaction, with schema validation and operational-attribute
stamping (`createTimestamp`, `entryUUID`, etc.) applied. Use it to populate a persistent storage backend before
`$server->run()`.

```php
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(
    new ServerOptions(PdoConfig::forSqlite('/var/lib/myapp/ldap.sqlite')),
);
$server->seed(
    new FileLdifLoader('/etc/myapp/initial-data.ldif'),
    new Dn('cn=admin,dc=example,dc=com'),
);

$server->run();
```

The optional second argument is the creator DN, stamped as `creatorsName`/`modifiersName` on each imported entry.
It defaults to the empty (anonymous) DN.

`seed()` accepts only content records (entries without `changetype:`) and requires depth-first input (parents first,
then children entries). LDIF produced by `dump()` is already in this order. The operation itself is an upsert that overwrites.

When using the Swoole runner (`setRunner(RunnerMode::Swoole)`), call `seed()` inside `Swoole\Coroutine\run()` so the
storage adapter's per-coroutine connection is available during import.

### Replaying LDIF Changelogs

`LdapServer::applyChanges()` replays an LDIF changelog through the live write path. Use it for applying diffs, migrations,
or administrative changes after the initial directory is populated.

```ldif
version: 1

dn: cn=alice,dc=example,dc=com
changetype: modify
replace: sn
sn: Anderson
-

dn: cn=bob,dc=example,dc=com
changetype: delete

dn: cn=carol,dc=example,dc=com
changetype: modrdn
newrdn: cn=carolyn
deleteoldrdn: 1
```

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(new ServerOptions($storageConfig));
$server->seed(new FileLdifLoader('/etc/myapp/initial-data.ldif'))
    ->applyChanges(new FileLdifLoader('/etc/myapp/changes-today.ldif'))
    ->run();
```

Unlike `seed()`, `applyChanges()` dispatches each request through the same write path the live server uses for client
requests. Supported changetypes: `add`, `delete`, `modify` (`add:`/`delete:`/`replace:` mod-specs), and `modrdn`/`moddn`
(rename or move; supports optional `newsuperior:` for moving across subtrees).

### Dumping the Directory

`LdapServer::dump()` streams the configured storage backend's entries to an LDIF output as RFC 2849 content records.
Operational attributes (`entryUUID`, `createTimestamp`, etc.) are preserved. So `dump()` then `seed()` restores the
entries exactly as they were.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Output\FileLdifOutput;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(
    new ServerOptions(PdoConfig::forSqlite('/var/lib/myapp/ldap.sqlite')),
);
$server->dump(new FileLdifOutput('/var/backups/ldap-snapshot.ldif'));
```

For in-memory use (logging, tests, piping over the network) use `StringLdifOutput`, which collects the chunks and is
both `Stringable` and exposes `getLdif()`:

```php
use FreeDSx\Ldap\Ldif\Output\StringLdifOutput;

$output = new StringLdifOutput();
$server->dump($output);

echo $output; // or $output->getLdif()
```

Use `DumpOptions` to filter the dump by any filter you want. Useful for partial backups or extracting a single OU:

```php
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Export\DumpOptions;

$options = (new DumpOptions())
    ->setBaseDn(new Dn('ou=people,dc=example,dc=com'))
    ->setFilter(Filters::equal('objectClass', 'inetOrgPerson'));

$server->dump(
    new FileLdifOutput('/tmp/people.ldif'),
    $options,
);
```

### Inspecting Parsed LDIF

For one-off tooling that needs to inspect a parsed LDIF before applying it (counting records, filtering by changetype,
etc) `LdifChanges` is a buffered collection with type filters:

```php
use FreeDSx\Ldap\Ldif\LdifChanges;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;

$changes = LdifChanges::fromLoader(new FileLdifLoader('/path/to/changes.ldif'));

foreach ($changes->entries() as $entry) {
    // each AddRequest's Entry
}

$changes->count();     // total changes
$changes->adds();      // AddRequest[]
$changes->modifies();  // ModifyRequest[]
$changes->deletes();   // DeleteRequest[]
$changes->modifyDns(); // ModifyDnRequest[]
```

`LdifChanges::fromString($ldif)` is the same flow for an in-memory string. The collection materializes every request,
so prefer the streaming `seed()`/`applyChanges()`/`dump()` methods normal data paths; `LdifChanges` is best suited to
small change sets.

## Authentication

The `PasswordAuthenticatableInterface` covers all bind types through two methods:

```php
interface PasswordAuthenticatableInterface
{
    // Called for simple binds.
    public function authenticate(
        string $name,
        string $password,
    ): AuthenticatedTokenInterface;

    // Called for all SASL mechanisms (PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM-*).
    // Return a SaslIdentity with the stored password and resolved DN, or null to reject.
    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity;
}
```

### Default Authentication

When no explicit authenticator is registered, we build a `PasswordAuthenticator` automatically. It
resolves the bind name to an entry via the backend's `get()` method (or a custom resolver — see below), then verifies
the supplied password against the `userPassword` attribute. Supported schemes: `{SHA}`, `{SSHA}`, `{MD5}`, `{SMD5}`,
and plaintext.

This means simple bind authentication works out of the box with any backend that stores `userPassword` on entries —
no additional configuration required.

### Custom Bind Name Resolution

By default, the built-in `PasswordAuthenticator` treats the bind name as a literal DN. If clients bind with a
non-DN identifier (a bare username, an email address, etc.), configure `AttributeSearchBindNameResolver` or
supply a custom `BindNameResolverInterface` via `setIdentityResolver()`:

```php
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\AttributeSearchBindNameResolver;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer(
    (new ServerOptions)->setIdentityResolver(
        new AttributeSearchBindNameResolver(
            baseDn: 'ou=People,dc=example,dc=com',
            attribute: 'mail',
        ),
    )
);
```

The resolver applies to simple bind, SASL bind, and Password Modify identity resolution. See
[Configuration](Configuration.md#setidentityresolver) for full details.

### Custom Authenticator

For full control — external auth services, custom credential storage, etc. — implement
`PasswordAuthenticatableInterface` and register it:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Sasl\Mechanism\MechanismName;
use SensitiveParameter;

class MyAuthenticator implements PasswordAuthenticatableInterface
{
    public function authenticate(
        string $name,
        #[SensitiveParameter]
        string $password,
    ): AuthenticatedTokenInterface {
        // Your simple-bind credential verification logic.
    }

    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        // Return a SaslIdentity with the stored password and resolved DN, or null to reject.
        // Challenge mechanisms require a plaintext or recoverable password.
    }
}

$server = new LdapServer((new ServerOptions())->setPasswordAuthenticator(new MyAuthenticator()));
```

## Handling the RootDSE

The server generates the RootDSE. `namingContexts` is derived from the backend storage contents; other attributes such
as `vendorName` come from `ServerOptions`. The entry always advertises:

- `supportedControl`: paging (RFC 2696)
- `supportedExtension`: WhoAmI (RFC 4532), Password Modify (RFC 3062), and StartTLS (RFC 4511) if an SSL certificate is configured
- `supportedLDAPVersion`: `3`

A `makeProxy()` server forwards RootDSE requests to the upstream automatically.

## SASL Authentication

The server supports SASL bind requests. SASL must be explicitly enabled by configuring the mechanisms you want to
support via `ServerOptions::setSaslMechanisms()`. The configured mechanisms are advertised to clients through the
`supportedSaslMechanisms` RootDSE attribute.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer(
    (new ServerOptions)->setSaslMechanisms(
        ServerOptions::SASL_PLAIN,
        ServerOptions::SASL_SCRAM_SHA_256,
    )
);
```

All SASL mechanisms are handled through `PasswordAuthenticatableInterface`. No separate interface or backend
modification is needed.

### PLAIN Mechanism

The `PLAIN` mechanism extracts the username and password from the SASL credentials and calls
`PasswordAuthenticatableInterface::getSaslIdentity()`. The built-in `PasswordAuthenticator` then verifies the
supplied password against the stored `userPassword` using `PasswordHashVerifier`, which supports `{SHA}`, `{SSHA}`,
`{MD5}`, `{SMD5}`, and plaintext. No additional configuration is needed beyond enabling the mechanism.

**Note**: PLAIN transmits credentials in cleartext. Only enable it when the connection is protected by TLS (StartTLS
or `setUseSsl`).

### Challenge-Based Mechanisms (CRAM-MD5, DIGEST-MD5, and SCRAM)

`CRAM-MD5`, `DIGEST-MD5`, and the `SCRAM-*` family are challenge-response mechanisms. The server issues a challenge
to the client and verifies the response against a digest computed from the user's plaintext password. The server calls
`PasswordAuthenticatableInterface::getSaslIdentity()` to retrieve the password.

The built-in `PasswordAuthenticator` reads the raw `userPassword` attribute from the resolved entry. This works when
passwords are stored in plaintext. If passwords are stored as one-way hashes (bcrypt, argon2) you must supply a
custom authenticator that can return a recoverable value.

**Note**: Because challenge mechanisms require a recoverable password, they are fundamentally incompatible with
one-way hashing. If one-way hashing is a hard requirement, use `PLAIN` over TLS instead.

### Identity Resolution for SASL

The built-in `PasswordAuthenticator` resolves SASL identities using a resolver chain. A full DN is tried first;
if that lookup returns no entry, the configured resolver (or `AttributeSearchBindNameResolver` searching by `uid`
by default) is applied. This same chain also drives simple bind and Password Modify identity resolution.

Configure the resolver via `setIdentityResolver()` when your directory uses a different attribute or a restricted
search base:

```php
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\AttributeSearchBindNameResolver;
use FreeDSx\Ldap\ServerOptions;

$options = (new ServerOptions)
    ->setIdentityResolver(
        new AttributeSearchBindNameResolver(
            baseDn: 'ou=People,dc=example,dc=com',
            attribute: 'mail',
        ),
    );
```

**SCRAM variants**: The following constants are available. `SCRAM-SHA-256` is the recommended choice for new
deployments ([RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) standardises it as the preferred mechanism).

| Constant                             | Mechanism                       |
|--------------------------------------|---------------------------------|
| `ServerOptions::SASL_SCRAM_SHA_1`    | `SCRAM-SHA-1`                   |
| `ServerOptions::SASL_SCRAM_SHA_256`  | `SCRAM-SHA-256` *(recommended)* |
| `ServerOptions::SASL_SCRAM_SHA_384`  | `SCRAM-SHA-384`                 |
| `ServerOptions::SASL_SCRAM_SHA_512`  | `SCRAM-SHA-512`                 |
| `ServerOptions::SASL_SCRAM_SHA3_512` | `SCRAM-SHA3-512`                |

Channel-binding (`-PLUS`) variants of each are also available (e.g. `SASL_SCRAM_SHA_256_PLUS`) for environments where
TLS channel binding is required.

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

## Password Modify Extended Operation

The server supports RFC 3062 Password Modify (OID `1.3.6.1.4.1.4203.1.11.1`). Authenticated clients may change
their own password or — if permitted by the configured access control — another user's password.

### Self-service password change

A client changes its own password by omitting `userIdentity`. The server resolves the target entry from the bound
DN. Supply the current password in `oldPassword` for verification:

```php
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;

$client->sendAndReceive(
    new PasswordModifyRequest(null, 'currentPassword', 'newPassword'),
);
```

### Server-generated passwords

Omit `newPassword` to let the server generate a secure random password. The generated password is returned in the
response:

```php
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;

/** @var PasswordModifyResponse $response */
$response = $client->sendAndReceive(
    new PasswordModifyRequest(null, 'currentPassword', null),
)->getResponse();

$generated = $response->getGeneratedPassword(); // 16-character random string
```

### Admin password reset

An admin may reset another user's password by supplying a `userIdentity`. The identity is resolved using the same
chain as bind operations — a full DN, or any name your configured `setIdentityResolver()` understands:

```php
$client->sendAndReceive(
    new PasswordModifyRequest('cn=user,dc=example,dc=com', null, 'resetPassword'),
);
```

### Access control

Password Modify is protected at two levels:

1. **Operation level** (`OperationType::PasswordModify`) — controls who may invoke the operation.
2. **Attribute level** (`userPassword`) — controls who may write the password attribute.

See [Access Control](Access-Control.md) for rule configuration. Anonymous access is always denied before the
handler runs when `requireAuthentication` is enabled (the default).
