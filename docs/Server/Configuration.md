LDAP Server Configuration
================

* [General Options](#general-options)
    * [ServerOptions:setLogger](#setlogger)
    * [ServerOptions:setEventLogPolicy](#seteventlogpolicy)
    * [ServerOptions:setRequireAuthentication](#setrequireauthentication)
    * [ServerOptions:setAllowAnonymous](#setallowanonymous)
    * [ServerOptions:setRequireConfidentiality](#setrequireconfidentiality)
* [Network Configuration](#network-configuration)
    * [NetworkConfig:setIp](#setip)
    * [NetworkConfig:setPort](#setport)
    * [NetworkConfig:setUnixSocket](#setunixsocket)
    * [NetworkConfig:setTransport](#settransport)
    * [NetworkConfig:setIdleTimeout](#setidletimeout)
    * [NetworkConfig:setWriteTimeout](#setwritetimeout)
    * [NetworkConfig:setRequestReadTimeout](#setrequestreadtimeout)
    * [NetworkConfig:setSocketAcceptTimeout](#setsocketaccepttimeout)
    * [NetworkConfig:setMaxConnections](#setmaxconnections)
    * [NetworkConfig:setMaxRequestSize](#setmaxrequestsize)
    * [NetworkConfig:setMaxAnonymousRequestSize](#setmaxanonymousrequestsize)
    * [NetworkConfig:setMaxRequestElements](#setmaxrequestelements)
    * [NetworkConfig:setMaxHeldRequestSize](#setmaxheldrequestsize)
    * [TLS](#tls)
        * [NetworkConfig:setUseSsl](#setusessl)
        * [NetworkConfig:setSslCert](#setsslcert)
        * [NetworkConfig:setSslCertKey](#setsslcertkey)
        * [NetworkConfig:setSslCertPassphrase](#setsslcertpassphrase)
        * [NetworkConfig:setMinTlsVersion](#setmintlsversion)
        * [NetworkConfig:setSslCiphers](#setsslciphers)
        * [NetworkConfig:setSslValidateCert](#setsslvalidatecert)
        * [NetworkConfig:setSslAllowSelfSigned](#setsslallowselfsigned)
        * [NetworkConfig:setSslCaCert](#setsslcacert)
        * [NetworkConfig:setSslHandshakeTimeout](#setsslhandshaketimeout)
* [Request Limits](#request-limits)
* [Access Control](#access-control)
    * [ServerOptions:setAclRules](#setaclrules)
* [Storage](#storage)
    * [ServerOptions:setStorageConfig](#setstorageconfig)
* [Authentication](#authentication)
    * [ServerOptions:setPasswordAuthenticator](#setpasswordauthenticator)
    * [ServerOptions:setIdentityResolver](#setidentityresolver)
    * [PasswordConfig:setHashing](#passwordconfigsethashing)
    * [PasswordConfig:setHashLimits](#passwordconfigsethashlimits)
    * [PasswordConfig:setAllowPreHashedPasswords](#passwordconfigsetallowprehashedpasswords)
    * [PasswordConfig:setMaxPasswordValues](#passwordconfigsetmaxpasswordvalues)
* [Schema](#schema)
    * [SchemaConfig:setSources](#schemaconfigsetsources)
    * [SchemaConfig:setValidationMode](#schemaconfigsetvalidationmode)
    * [SchemaConfig:setLoadMode](#schemaconfigsetloadmode)
* [RootDSE Options](#rootdse-options)
    * [ServerOptions:setDseAltServer](#setdsealtserver)
    * [ServerOptions:setDseVendorName](#setdsevendorname)
    * [ServerOptions:setDseVendorVersion](#setdsevendorversion)
* [Search Limits](#search-limits)
    * [ServerOptions:setMaxSearchSize](#setmaxsearchsize)
    * [ServerOptions:setMaxSearchTimeLimit](#setmaxsearchtimelimit)
    * [ServerOptions:setMaxSearchPageSize](#setmaxsearchpagesize)
    * [ServerOptions:setMaxSearchLookthrough](#setmaxsearchlookthrough)
    * [ServerOptions:setMaxSearchPagedLookthrough](#setmaxsearchpagedlookthrough)
    * [ServerOptions:setMaxPagingSessions](#setmaxpagingsessions)
    * [ServerOptions:setSearchLimitRules](#setsearchlimitrules)
* [Directory Synchronization](#directory-synchronization)
    * [ServerOptions:setReplicationConfig](#setreplicationconfig)
    * [ServerOptions:setChangeJournalConfig](#setchangejournalconfig)
* [Read-Only Replica](#read-only-replica)
    * [ConsumerConfig:setBind](#setbind)
    * [ConsumerConfig:setUseStartTls](#setusestarttls)
    * [ConsumerConfig:setReferWrites](#setreferwrites)
    * [ConsumerConfig:setFilter](#setfilter)
    * [ConsumerConfig:setReconnectBackoff](#setreconnectbackoff)
    * [ConsumerConfig:setForwardInterval](#setforwardinterval)
* [SASL Options](#sasl-options)
    * [ServerOptions:setSaslMechanisms](#setsaslmechanisms)
    * [ServerOptions:setExternalCredentialMapper](#setexternalcredentialmapper)

The LDAP server is configured through a `ServerOptions` object. The configuration object is passed to the server
on construction:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Config\NetworkConfig;

$options = (new ServerOptions(network: NetworkConfig::withPort(33389)))
  ->setDseAltServer('dc2.local');

$ldap = new LdapServer($options);
```

The following documents these various configuration options and how they impact the server.

## General Options

------------------
#### setLogger

Specify a PSR-3 compatible logging instance to use. The server emits structured audit events
(bind outcomes, authorization details, schema violations, etc.) through this logger. See
[Server Logging](Logging.md) for the full event catalog and log properties.

You can also set the logger on your options instance before running the server:

```php
use FreeDSx\Ldap\ServerOptions;

// with your current options instance
$options->setLogger($logger);
```

**Default**: `null`

------------------
#### setEventLogPolicy

Tune which catalogued events the server emits. By default, security-relevant events are on
(bind outcomes, ACL denials, schema violations, StartTLS, Notice of Disconnect); high-volume
per-operation success events are off and opt-in via `withAuditTrail()`. Full exception traces
on `ldap.session.disconnect_notice` events are also opt-in via `withExceptionTraces()`.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;

$options = (new ServerOptions($storageConfig))
    ->setEventLogPolicy(EventLogPolicy::default()->withAuditTrail());
```

See [Server Logging](Logging.md) for the full event catalog, the context-key reference, and
the policy API.

**Default**: `EventLogPolicy::default()`

------------------
#### setRequireAuthentication

Whether authentication (bind) should be required before an operation is allowed.

**Note**: Certain LDAP operations implicitly do not require authentication: StartTLS, RootDSE requests, WhoAmI

**Default**: `true`

------------------
#### setAllowAnonymous

Whether anonymous binds should be allowed. Governs both RFC 4513 mechanisms: an anonymous bind (empty DN and
password) and an unauthenticated bind (a DN with an empty password). Either way the connection ends up
anonymous, so the DN carries no authorization.

Reading the RootDSE needs no bind at all, so leaving this off does not prevent discovery.

**Default**: `false`

------------------
#### setRequireConfidentiality

How much of a session the server refuses to serve over an unprotected connection.

```php
use FreeDSx\Ldap\Server\Config\ConfidentialityRequirement;

$options->setRequireConfidentiality(ConfidentialityRequirement::CredentialBind);
```

| Value            | Effect                                                                              |
|------------------|-------------------------------------------------------------------------------------|
| `None`           | Nothing is refused, including a password sent in the clear.                          |
| `CredentialBind` | Refuses simple binds and SASL binds other than EXTERNAL. Anonymous reads still work. |
| `AllOperations`  | Refuses every request apart from StartTLS, Unbind and Abandon.                       |

A connection satisfies the requirement when it is encrypted, through either `setUseSsl` or a completed StartTLS, or
when the transport is a unix socket. Configure [TLS](#tls) before turning this on, otherwise a unix transport is the
only way left to satisfy it.

**Default**: `ConfidentialityRequirement::None`

## Runner Configuration

The process model lives on `FreeDSx\Ldap\Server\Config\RunnerConfig`, passed as the third constructor argument to
`ServerOptions` or set with `setRunnerConfig()`. It selects the runner and, for Swoole, how many worker processes
accept connections.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\Config\RunnerConfig;

$options = new ServerOptions(
    $storageConfig,
    $networkConfig,
    // One worker per available CPU. Pass a count for a fixed number, or 1 for a single process.
    RunnerConfig::forSwoole(),
);
```

`RunnerConfig::forPcntl()` selects the forking runner, which is also the default.

#### setMode

`RunnerMode::Pcntl` forks a process per connection and is not available on Windows. `RunnerMode::Swoole` handles each connection in
its own coroutine and requires the Swoole extension.

**Default**: `RunnerMode::Pcntl`

#### setWorkers

Worker processes the Swoole runner accepts on. `1` runs a single process. `0` auto-detects, honouring container CPU
limits rather than the host total. The forking runner ignores this, since it already spans cores by forking.

**Default**: `1`

### Which backends can use more than one worker

Workers are separate processes, so a directory can only be served by several of them when its entries live outside the
process. Anything else is clamped back to a single worker with a logged warning.

| Storage | Multiple workers | Why |
| --- | --- | --- |
| PDO (`PdoConfig`) | Yes | The database is the shared state |
| In-memory (`InMemoryStorageConfig`) | No | Entries never leave the process that holds them |

A proxy has no local directory, so it can always use multiple workers.

### Concurrency Limits

The server logs `server.concurrency_limited` at startup when one of these limits how many clients it serves at once:

* `storage_not_shareable`: the storage cannot be shared between processes.
* `storage_blocks_worker`: a SQLite lock wait blocks a worker that serves many clients in one process.
* `open_file_limit`: `ulimit -n` is below the open files a worker that serves many clients in one process needs at the
  connection limit.
* `memory_limit`: a worker that serves many clients in one process can run out of memory before the connection limit.
* `held_request_size`: [setMaxHeldRequestSize](#setmaxheldrequestsize) is smaller than the largest request allowed, or
  requests have no size limit.
* `no_memory_limit`: `memory_limit` is `-1`, leaving the held request size at a fixed 512 MiB.

### Signals

| Signal | Single process | Worker pool |
| --- | --- | --- |
| `SIGHUP` | Reloads configuration in place | Ignored by the pool master; send it to the **process group** to reload every worker in place |
| `SIGUSR1` | Not used | Swoole restarts each worker in turn, which drops paged searches and sync streams; prefer `SIGHUP` |
| `SIGTERM` / `SIGINT` / `SIGQUIT` | Drains, then exits | Every worker drains, then the pool exits |

Reloading a pool in place means sending `SIGHUP` to the process group rather than to the master alone, because the pool
master cannot forward signals:

```bash
kill -HUP -$(ps -o pgid= -p "$MASTER_PID" | tr -d ' ')
```

Each worker adopts the new configuration in place, so nothing is dropped. A worker that dies is respawned by the pool and runs with the latest configuration.

## Network Configuration

The listen socket, timeouts, and TLS settings live on `FreeDSx\Ldap\Server\Config\NetworkConfig`, not on
`ServerOptions`. Reach it either by passing a `NetworkConfig` as the second constructor argument (the storage config is
first), or through `getNetworkConfig()` on an existing options instance. `ProxyServerOptions` exposes the same
`getNetworkConfig()` accessor and `new ProxyServerOptions(NetworkConfig)` constructor.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\Config\NetworkConfig;

// On construction, as the second argument.
$options = new ServerOptions(
    network: (new NetworkConfig())
        ->setPort(636)
        ->setUseSsl(true),
);

// Or on an existing options instance.
$options->getNetworkConfig()->setPort(636);
```

`NetworkConfig::withPort(int $port): self` is a shortcut for the common port-only case:
`new ServerOptions(network: NetworkConfig::withPort(10389))`.

------------------
#### setIp

The IP address to bind and listen to while the server is running. By default it will bind to `0.0.0.0`, which will listen
on all IP addresses of the machine.

**Default**: `0.0.0.0`

------------------
#### setPort

The port to bind to and accept client connections on. By default this is port 389. Since this port is underneath the
first 1024 ports, it will require administrative access when running the server. You can change this to something higher
than 1024 instead if needed.

**Default**: `389`

------------------
#### setUnixSocket

When using `unix` as the transport type, this is the full path to the socket file the client must interact with.

**Default**: `/var/run/ldap.socket`

------------------
#### setTransport

The transport mechanism for the server to use. Use either:

* `tcp`
* `unix`

If using `unix` for the transport you can change set the `unix_socket` to a file path representing the unix socket the clients must connect to.

**Default**: `tcp`

------------------
#### setIdleTimeout

Consider an idle client to timeout after this period of time (in seconds) and disconnect their LDAP session. If set to
-1, the client can idle indefinitely and not timeout the connection to the server.

**Default**: `600`

------------------
#### setWriteTimeout

Disconnect a client whose response send makes no progress for this many seconds (a reader that has stopped draining).
Nothing more is written to it once a write fails. Set to `0` to disable.

**Default**: `30`

------------------
#### setRequestReadTimeout

Disconnect a client whose request takes longer than this many seconds to finish arriving. Set `0` to disable.

```php
$options->getNetworkConfig()->setRequestReadTimeout(60);
```

Raise it if clients on slower links send large requests.

**Default**: `30`

------------------
#### setSocketAcceptTimeout

The number of seconds (fractional) to wait for a new client connection before re-checking server state. Lower values
make the server more responsive to shutdown signals and connection-limit changes at the cost of slightly more CPU usage
in the accept loop.

**Default**: `0.5`

------------------
#### setMaxConnections

The most concurrent client connections the whole server accepts, on every runner. Once reached, further connections
are closed without being served, and `connectionsRejected` in [cn=monitor](Monitoring.md) counts them. Set `0` for no
limit.

```php
$options->getNetworkConfig()->setMaxConnections(4096);
```

The Pcntl runner forks a process per connection, so this bounds process count rather than memory alone. Pick a value
the host can fork. A worker that serves many clients in one process also needs `ulimit -n` above this limit times the
open files each client holds (up to 3).

**Default**: `1024`

------------------
#### setMaxRequestSize

The largest request, in bytes, the server reads from a client. A larger request is answered with a notice of
disconnection (protocolError) and the connection is closed, which `connectionsRequestSizeExceeded` in
[cn=monitor](Monitoring.md) counts. The proxy server applies it the same way. Set `0` for no limit.

Until a client completes an authenticated bind, the smaller
[setMaxAnonymousRequestSize](#setmaxanonymousrequestsize) applies instead.

```php
$options->getNetworkConfig()->setMaxRequestSize(1_048_576);
```

Raising it also raises the memory a single request can cost a worker. A request is held to
[setMaxRequestElements](#setmaxrequestelements) as well, which a large request of many small values may reach first.

**Default**: `2621440` (2.5 MiB)

------------------
#### setMaxAnonymousRequestSize

The largest request, in bytes, the server reads from a client without an authenticated bind. This covers a client that
has not bound, one that bound anonymously, and one whose last bind failed. A larger request is handled the same way as
one past [setMaxRequestSize](#setmaxrequestsize), which still applies when it is the smaller of the two. Set `0` to
apply only `setMaxRequestSize`.

```php
$options->getNetworkConfig()->setMaxAnonymousRequestSize(0);
```

Set it to `0`, or raise it, if clients write large entries without binding.

**Default**: `262144` (256 KiB)

------------------
#### setMaxRequestElements

The most ASN.1 elements a request may hold. A request with more is answered with a notice of disconnection
(protocolError) and the connection is closed, which `connectionsRequestSizeExceeded` in [cn=monitor](Monitoring.md)
counts. When the extra elements are inside a filter, a control, SASL bind credentials or an extended operation's value,
the request is answered with `ADMIN_LIMIT_EXCEEDED` instead and the connection stays open. Set `0` for no limit.

```php
$options->getNetworkConfig()->setMaxRequestElements(200_000);
```

At the default, one request can carry about 100,000 attribute values. Raise it along with
[setMaxRequestSize](#setmaxrequestsize) if clients send more.

**Default**: `100000`

------------------
#### setMaxHeldRequestSize

The most memory, in bytes, the requests of one process may hold at once. Each process has its own. A request with no room
is answered with `BUSY`, and one that could never fit is refused. Set `0` for no limit.

One identity may hold a quarter of it, but never less than what the largest request allowed holds:

* The identity is the one the connection is bound as, however its DN is spelled.
* Every connection that has not bound, bound anonymously or failed its last bind counts as one identity. Anonymous
  clients can make each other wait.
* With no request size limit, one identity may hold all of it.
* While an identity holds all it may, its connections stop reading ahead, so an Abandon or Cancel sent during one of
  their searches is not seen until that search ends.

The entries a page of a paged search collects before it is written count too. A page ends early with a cookie to
continue from when there is no room for its next entry, and is answered with `BUSY` when there is no room for its first.

```php
$options->getNetworkConfig()->setMaxHeldRequestSize(134_217_728);
```

**Default**: half of `memory_limit`, or 512 MiB when there is none

### TLS

The StartTLS and LDAPS settings below are also part of `NetworkConfig`. Configure them on the network config passed to
the `ServerOptions` constructor, or via `getNetworkConfig()`.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\Config\NetworkConfig;

$options = new ServerOptions(
    network: (new NetworkConfig())
        ->setUseSsl(true)
        ->setSslCert('/path/to/cert.pem')
        ->setSslCertKey('/path/to/key.pem'),
);
```

------------------
#### setUseSsl

If set to true, and the transport is `tcp`, the server will use an SSL stream to bind to the IP address. This forces clients
to use an encrypted stream only for communication to the server.

**Note**: LDAP over SSL, commonly referred to as LDAPS, is not an official LDAP standard. Support is dependent on the client / server specific implementations.

**Default**: `false`

------------------
#### setSslCert

The server certificate to use for clients issuing StartTLS commands to encrypt their TCP session.

**Note**: If no certificate is provided clients will be unable to issue a StartTLS operation.

**Default**: `(null)`

------------------
#### setSslCertKey

The server certificate private key. This can also be bundled with the certificate in the `NetworkConfig::setSslCert` option.

**Default**: `(null)`

------------------
#### setSslCertPassphrase

The passphrase needed for the server certificate's private key.

**Default**: `(null)`

------------------
#### setMinTlsVersion

The minimum TLS protocol version the server will negotiate for StartTLS and LDAPS sessions. Provide a
`FreeDSx\Ldap\Server\TlsVersion` case (`Tls1_0`, `Tls1_1`, `Tls1_2`, `Tls1_3`); the server accepts that version and any
higher one. The default rejects the deprecated TLS 1.0 and 1.1 (RFC 8996); lower it explicitly only for legacy clients.

```php
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\TlsVersion;

$network = (new NetworkConfig())
    ->setMinTlsVersion(TlsVersion::Tls1_3);
```

**Default**: `TlsVersion::Tls1_2`

------------------
#### setSslCiphers

The OpenSSL cipher list (in OpenSSL cipher-string format) offered during the TLS handshake.

**Default**: `DEFAULT`

------------------
#### setSslValidateCert

Whether the server requires and verifies a client certificate (mutual TLS). When enabled, provide the trust anchors via
`setSslCaCert` so client certificates can be validated.

**Default**: `false`

------------------
#### setSslAllowSelfSigned

Whether a self-signed client certificate is accepted when `setSslValidateCert` is enabled. `null` leaves the underlying
default (not allowed).

**Default**: `(null)`

------------------
#### setSslCaCert

Path to a CA certificate bundle used to verify client certificates when `setSslValidateCert` is enabled.

**Default**: `(null)`

------------------
#### setSslHandshakeTimeout

Seconds a TLS handshake may take before the connection is dropped. This bounds a client that connects and then stalls,
which would otherwise hold the connection for the whole idle timeout.

```php
$options->getNetworkConfig()->setSslHandshakeTimeout(10);
```

Raise it if legitimate clients on slow links fail to connect.

**Default**: `5`

## Request Limits

Limits on each request the server reads from a client, which the proxy server applies the same way. A request past one
either ends the connection with a notice of disconnection (protocolError), or is refused with a result code and the
connection stays open.

Configurable:

* **Request size:** 2.5 MiB ([setMaxRequestSize](#setmaxrequestsize)). A larger request ends the connection.
* **Request size before an authenticated bind:** 256 KiB
  ([setMaxAnonymousRequestSize](#setmaxanonymousrequestsize)). A larger request ends the connection.
* **ASN.1 elements:** 100,000 ([setMaxRequestElements](#setmaxrequestelements)). More ends the connection, or is
  refused with `ADMIN_LIMIT_EXCEEDED` when the extra elements are inside a filter, a control, SASL bind credentials or
  an extended operation's value.
* **Time to arrive:** 30 seconds ([setRequestReadTimeout](#setrequestreadtimeout)). A slower request ends the
  connection.
* **Memory held at once:** half of `memory_limit` per process ([setMaxHeldRequestSize](#setmaxheldrequestsize)), a
  quarter of it per identity. A request with no room is refused with `BUSY`.

Fixed:

* **ASN.1 nesting:** 16 levels.
* **Filter items:** 1,000 in a search or an assertion control, each part of a substring item and each empty AND or OR
  counting as one.
* **Filter nesting:** 30 levels of AND, OR and NOT.
* **Modify changes:** 1,000 per modify request.
* **Selected attributes:** 1,000 in a search, a Pre-Read control or a Post-Read control.
* **Sort keys:** 100 in a sorting control.
* **Controls:** 100 per request.

## Access Control

------------------
#### setAclRules

Configure the built-in rule engine with an `AclRules` bundle (operation, attribute, and control rules plus their
default effects). The server builds a `RuleBasedAccessControl` from it automatically.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;

$server = new LdapServer(
    (new ServerOptions($storageConfig))
        ->setAclRules(
            AclRules::fromEmpty()->replaceOperationRules(
                OperationRule::allow(Subject::authenticated()),
                OperationRule::deny(Subject::anyone()),
            ),
        )
);
```

See [Access Control](Access-Control.md) for rule evaluation, subject/target matchers, attribute rules, and the
control-rule grants for privileged controls (e.g. Relax Rules).

**Default**: `AclRules::secureDefault()`. See [Access Control](Access-Control.md).

## Storage

------------------
#### setStorageConfig

Where directory data lives, set with `setStorageConfig()` or by passing the config to the `ServerOptions` constructor.
All directory operations are dispatched to the resulting storage.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(new ServerOptions(PdoConfig::forSqlite('/var/lib/myapp/ldap.sqlite')));
```

A config is required, as no default suits every runner. For the available configs see
[Built-In Storage Implementations](General-Usage.md#built-in-storage-implementations), and for the options each one
carries see [Tuning a PDO config](General-Usage.md#tuning-a-pdo-config).

**Default**: none, a config must be provided.

## Authentication

------------------
#### setPasswordAuthenticator

This should be an object instance that implements `FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface`.
It handles all password-based bind authentication through two methods:

* `authenticate(string $name, string $password): AuthenticatedTokenInterface` — called for simple binds
* `getSaslIdentity(string $username, MechanismName $mechanism): ?SaslIdentity` — called for all SASL mechanisms
  (PLAIN, CRAM-MD5, SCRAM-*). Returns the stored password and resolved DN, or `null` to reject.

Every mechanism except PLAIN uses the returned value as the shared secret, so a hash would become the password. The
built-in authenticator returns `null` for those mechanisms when the stored value is hashed, and a custom one should
do the same.

The server resolves an authenticator in this order:

1. An explicit instance set via `setPasswordAuthenticator()`
2. The backend, if it implements `PasswordAuthenticatableInterface`
3. A built-in `PasswordAuthenticator` that resolves the bind name to an entry via the configured
   `BindNameResolverInterface` and verifies the entry's `userPassword` attribute

Use this option when you need to delegate authentication to an external system (a database, an upstream LDAP server,
an identity provider, etc.) without implementing the storage backend interface:

```php
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Sasl\Mechanism\MechanismName;

class ExternalAuthenticator implements PasswordAuthenticatableInterface
{
    public function authenticate(
        string $name,
        #[\SensitiveParameter] string $password,
    ): AuthenticatedTokenInterface {
        // Verify the password and return a token representing the bound identity.
    }

    public function getSaslIdentity(
        string $username,
        MechanismName $mechanism,
    ): ?SaslIdentity {
        // Resolve the SASL identity to an entry. Return null to reject the bind.
        // Challenge mechanisms (CRAM-MD5, SCRAM-*) require a plaintext
        // or recoverable password; one-way hashes (bcrypt, argon2) cannot be used.
        return null;
    }
}
```

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer(
    (new ServerOptions)
        ->setPasswordAuthenticator(new ExternalAuthenticator())
);
```

**Note**: Challenge-based mechanisms (CRAM-MD5, SCRAM-*) require `getSaslIdentity()` to return a
`SaslIdentity` with a plaintext or recoverable password. Return `null` to reject SASL for that user.

**Default**: `null` (resolved automatically as described above)

------------------
#### setIdentityResolver

This should be an object instance that implements `FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface`.
It controls how the built-in `PasswordAuthenticator` and the Password Modify handler translate a bind name or user
identity into a directory entry.

The resolver is consulted in three places:

- **Simple bind** — translates the raw bind name to an entry for password verification
- **SASL bind** — translates the SASL username to an entry for identity resolution
- **Password Modify** — translates the `userIdentity` field in an RFC 3062 request to the target entry

The server always tries `DnBindNameResolver` first (treats the name as a literal DN). It
falls back to the configured resolver or (if none is set) `AttributeSearchBindNameResolver` (searches for an
entry where `uid` equals the name, starting from the directory root).

Configure `AttributeSearchBindNameResolver` when clients bind with a non-DN identifier and your directory uses a
different attribute or a restricted search base:

```php
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\AttributeSearchBindNameResolver;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer(
    (new ServerOptions)
        ->setIdentityResolver(
            new AttributeSearchBindNameResolver(
                baseDn: 'ou=People,dc=example,dc=com',
                attribute: 'mail',
            ),
        )
);
```

For fully custom logic, implement `BindNameResolverInterface` and supply it here.

**Note**: If you provide a fully custom authenticator via `setPasswordAuthenticator()`, name resolution for bind
operations is your responsibility and this option has no effect on bind authentication. It still applies to
Password Modify requests.

**Default**: `null` (`DnBindNameResolver` is tried first; falls back to `AttributeSearchBindNameResolver`)

------------------
#### PasswordConfig:setHashing

The scheme and work factor Password Modify hashes a new password with: `PasswordHashing::argon2id()`,
`PasswordHashing::bcrypt()` or `PasswordHashing::ssha()`. Values already stored keep verifying under their own scheme.
`{CRYPT}` and `{BCRYPT}` never match a password holding a NUL byte. While bcrypt is the configured scheme, Password
Modify refuses a new password holding one, or longer than the 72 bytes bcrypt reads, with `constraintViolation`.

```php
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\Config\PasswordHashing;

$options->setPasswordConfig(
    (new PasswordConfig())->setHashing(PasswordHashing::argon2id(
        memoryKiB: 19456,
        passes: 2,
    )),
);
```

**Default**: `PasswordHashing::argon2id()`, with 7 MiB of memory, 5 passes and 1 thread

------------------
#### PasswordConfig:setHashLimits

The most work a stored password hash may ask for. A hash over a limit is refused on write and never verifies. Any
password check that meets one logs `ldap.password.hash_over_limits`: a bind, an old password check, or the password
history check. The limits never fall below the configured hashing.

`maxPasswordLength` caps the bytes of a password the server verifies, since some schemes cost more the longer it is. A
longer password fails to bind, and a cleartext `userPassword` or Password Modify new password over it is refused with
`constraintViolation`. It cannot be set below 16, the length of a generated password.

```php
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\Config\PasswordHashLimits;

$options->setPasswordConfig(new PasswordConfig(
    new PasswordHashLimits(
        bcryptCost: 12,
        maxPasswordLength: 256,
    ),
));
```

**Default**: SHA crypt 1,000,000 rounds, bcrypt cost 14, extended DES 1,000,000 rounds, argon2 256 MiB of memory,
memory times passes of 1 GiB and 4 threads, and passwords of 512 bytes

------------------
#### PasswordConfig:setAllowPreHashedPasswords

Whether any writer may store a pre-hashed `userPassword` value, one starting with a `{SCHEME}` prefix. When off, only
[administrators](Access-Control.md#administrators), the manager and server writes (such as seeding) may.

**Default**: `false`

------------------
#### PasswordConfig:setMaxPasswordValues

How many `userPassword` values an entry may hold, counting those under attribute options. A failed simple bind verifies
each value it reads. An entry already over the limit keeps its values but cannot gain more. The core schema also caps
each `userPassword` description at one value (`X-MAX-VALUES`), so raising this takes a schema override too. Under
`Strict` or `Lenient` validation, that cap refuses every write to an entry over it until its passwords are replaced.
A bind to such an entry is still answered by its password, but its password policy state is not recorded, and
`ldap.password_policy.state_not_recorded` is logged naming the entry.

**Default**: `1`

## Schema

The schema is configured with a `SchemaConfig`, passed to `ServerOptions` alongside the other configuration
objects. For full documentation, see [Schema Validation](Schema.md).

```php
use FreeDSx\Ldap\Server\Config\SchemaConfig;
use FreeDSx\Ldap\ServerOptions;

$schemaConfig = new SchemaConfig();

$options = new ServerOptions(schemaConfig: $schemaConfig);
```

`getSchemaConfig()` returns the config in use, so the defaults can be adjusted without constructing one:

```php
$options = new ServerOptions($storageConfig);

$options->getSchemaConfig()
    ->addSource(new LdifSchemaSource('/path/to/schema.ldif'));
```

------------------
#### SchemaConfig:setSources

The schemas the server enforces and publishes, merged in the order given. See
[Custom Schema](Schema.md#custom-schema). Use `addSource()` to append to the shipped set rather than replace it.

**Default**: `[SchemaResource::Core, SchemaResource::Nis, SchemaResource::PasswordPolicy]`

------------------
#### SchemaConfig:setValidationMode

How `add`/`modify` writes are validated:

* `Strict` rejects violations
* `Lenient` logs them but allows the write
* `Off` skips validation

See [Validation Mode](Schema.md#validation-mode).

**Default**: `SchemaValidationMode::Strict`

------------------
#### SchemaConfig:setLoadMode

Whether a definition referencing something no source provides fails the load. See
[SchemaLoadMode](Schema.md#schemaloadmode).

**Default**: `SchemaLoadMode::Strict`

## RootDSE Options

The `namingContexts` attribute is derived from the backend. No configuration is needed.

------------------
#### setDseAltServer

The altServer attribute for the RootDSE. These should be alternate servers to be used if this one becomes unavailable.

**Default**: `(null)`

------------------
#### setDseVendorName

The vendorName attribute for the RootDSE.

**Default**: `FreeDSx`

------------------
#### setDseVendorVersion

The vendorVersion attribute for the RootDSE.

**Default**: `(null)`

## Search Limits

Server-side caps applied independently of what the client requests. When both the client and server specify a limit, the
stricter value wins. A server value of `0` means no server-side cap.

Limits on the search request itself, such as how many items its filter may hold, are listed under
[Request Limits](#request-limits).

------------------
#### setMaxSearchSize

Maximum number of entries the server will return for any single search. When the cap is reached the server returns a
`SIZE_LIMIT_EXCEEDED` result code and stops sending entries.

**Default**: `1000`

------------------
#### setMaxSearchTimeLimit

Maximum number of seconds a search operation may run. When exceeded the server returns a `TIME_LIMIT_EXCEEDED` result
code.

**Default**: `120`

------------------
#### setMaxSearchPageSize

The maximum number of entries the server will return per page in a paged search. When the client requests a larger page size
(or sends `0` meaning "server decides"), this cap is applied. A page can also hold fewer entries when the memory its
client may hold runs out ([setMaxHeldRequestSize](#setmaxheldrequestsize)).

**Default**: `1000`

------------------
#### setMaxSearchLookthrough

Maximum number of entries the server will examine while evaluating a search before returning an `ADMIN_LIMIT_EXCEEDED`
result code. Unlike the size limit (entries returned), this caps entries inspected, so it bounds an unindexed filter that
scans many entries to return few. Raise it above the largest legitimate subtree a client may scan, or set `0` to disable.

**Default**: `5000`

> Every entry the server examines counts, whether it was examined to evaluate the filter or to decide what the client is
> allowed to see. Each page of a paged search is counted on its own (see `setMaxSearchPagedLookthrough`).

------------------
#### setMaxSearchPagedLookthrough

A separate lookthrough cap for paged searches, counted per page. Filling a page examines more candidates than an ordinary
search, so this raises the cap for paging without loosening `setMaxSearchLookthrough`.

**Default**: `0` (use the regular lookthrough limit)

------------------
#### setMaxPagingSessions

Cap how many paged searches one connection may leave unfinished, since each holds its place in the result until the
connection closes. Starting one past the cap discards the least recently started session, logged as
`ldap.paging.session_evicted`. A client resuming a discarded session is refused with an invalid cookie. A value of `0`
removes the cap.

**Default**: `25`

------------------
#### setSearchLimitRules

Per-identity search limits: an ordered list of `(subject, limits)` rules, evaluated first-match-wins. The first rule whose
subject matches the bound identity supplies that request's limits; identities matching no rule get the global limits above.

A rule overrides only the limits it names. Anything it leaves unset keeps the global value. Naming a limit as `0` is an
explicit "no limit" for that identity, which is how a rule lifts a global cap rather than inheriting it.

```php
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRule;
use FreeDSx\Ldap\Server\SearchLimit\SearchLimitRules;
use FreeDSx\Ldap\Server\SearchLimits;

$rules = new SearchLimitRules([
    SearchLimitRule::for(
        Subject::anonymous(),
        new SearchLimits(
            maxSearchSize: 100,
            maxSearchLookthrough: 1000,
        ),
    ),
    SearchLimitRule::for(
        Subject::authenticated(),
        new SearchLimits(
            maxSearchSize: 1000,
            maxSearchLookthrough: 20000,
        ),
    ),
]);

$options->setSearchLimitRules($rules);
```

> Subjects reuse the access-control matchers (`Subject::anonymous()`, `Subject::authenticated()`, `Subject::dn()`,
> `Subject::group()`), so you can, for example, give anonymous binds a tight lookthrough while authenticated identities
> get a larger one.

**Default**: none (all identities use the global limits)

## Directory Synchronization

Record directory changes and serve them to RFC 4533 sync consumers. See [Directory Synchronization](Replication.md) for
the full guide, including the storage and runner requirements and the required access-control grant.

------------------
#### setReplicationConfig

The replication role the server plays, and its identity within the topology. `ReplicationConfig::forProvider()` answers
content-sync requests, `ReplicationConfig::forReplica()` mirrors an upstream. Serving sync also needs storage that
supports journaling (all built-in storage does) and the privileged sync control granted through access control. See
[Directory Synchronization](Replication.md).

```php
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Config\Replication\ProviderConfig;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;

$options->setReplicationConfig(
    ReplicationConfig::forProvider(
        (new ProviderConfig())->setPollInterval(1.0),
    )->setId(new ReplicaId('dc1')),
);
```

The identity is stamped into sync cookies, so give each provider a stable, unique one. The poll interval bounds how
quickly a persisting consumer sees a change, and how quickly the server notices a consumer that has gone away.

**Default**: no role, with the identity `local`.

------------------
#### setChangeJournalConfig

The change journal configuration: the retention policy that limits journal growth, and an optional audit sink. When the
policy sets at least one limit, the journal is pruned on a cadence. See [Retention](Replication.md#retention).

Recording changes and serving them are separate. A journal configured on its own records every write without making the
server a sync provider, which is what you want for auditing alone. Sync requests are then refused with
`unwillingToPerform`. A provider records regardless, so it has a journal whether or not you configure one.

```php
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Audit\JsonLinesAuditSink;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;

$options->setChangeJournalConfig(new ChangeJournalConfig(
    retention: new RetentionPolicy(maxRecords: 1_000_000),
    auditSink: new JsonLinesAuditSink('/var/log/freedsx/changes.jsonl'),
));
```

**Default**: `null`, so nothing is recorded unless a journal or a provider role is configured. A journal defaults to no
retention limits, meaning it is not pruned.

## Read-Only Replica

Run the server as a read-only replica that mirrors a provider over RFC 4533. See
[Read-Only Replica](Replication.md#read-only-replica) for the full guide.

The `ConsumerConfig` is constructed with the provider's `ClientOptions` (servers, TLS, and the base DN of the subtree to
mirror) and, optionally, a `ReplicationCheckpointInterface` where the sync cookie is persisted. The checkpoint defaults
to in-memory. Use `FileReplicationCheckpoint` in production so the replica resumes across restarts. The setters below
configure the rest.

Pass it as the replication role, which puts the server into read-only replica mode. Client writes are refused and a
background daemon keeps the local storage in step with the provider. A replica requires PDO storage. See
[Storage Requirement](Replication.md#storage-requirement).

```php
$options = new ServerOptions(
    storageConfig: PdoConfig::forSqlite('/var/lib/freedsx/replica.sqlite'),
    replicationConfig: ReplicationConfig::forReplica($consumerConfig),
);
```

------------------
#### setBind

A `ConsumerConfig` setter for how the replica authenticates to the provider, as a `BindRequest` from `Operations::bind()`
(simple) or `Operations::bindSasl()` (SASL, including EXTERNAL for client-certificate auth).

**Default**: none

------------------
#### setUseStartTls

A `ConsumerConfig` setter for whether to issue StartTLS on the provider connection before binding. LDAPS is configured on
the primary `ClientOptions` instead.

**Default**: `false`

------------------
#### setReferWrites

A `ConsumerConfig` setter for whether a client write to the replica is referred to the provider (`true`) or rejected with
`unwillingToPerform` (`false`).

**Default**: `true`

------------------
#### setFilter

A `ConsumerConfig` setter for an optional filter restricting which entries are replicated.

**Default**: `null` (all in-scope entries).

------------------
#### setReconnectBackoff

A `ConsumerConfig` setter for the bounded exponential backoff applied between reconnect attempts to the provider.

**Default**: `new ReconnectBackoff()` (starts at 1s, doubling to a 30s ceiling).

------------------
#### setForwardInterval

A `ConsumerConfig` setter for how long queued password-policy bind state waits before being forwarded to the provider.
Batching trades a slower global lockout against constant upstream chatter. Must be greater than zero.

**Default**: `5.0` seconds.

## Monitoring

Opt-in observability. See [Server Monitoring](Monitoring.md) for the full guide, the `cn=monitor` attributes, and the
push-exporter contract.

------------------
#### setMonitorEnabled

Whether to serve the server-generated `cn=monitor` entry. When off, the route is not registered.

**Default**: `false`

------------------
#### setMonitorSnapshotPath

PCNTL only. Path to the JSON file the parent publishes for `cn=monitor` to read. When unset, the parent creates a uniquely
named file in the system temp directory at startup and removes it on shutdown. A configured file that already exists must
belong to the server's user, or the server refuses to start.

**Default**: `null`

------------------
#### setMetricsRecorder

An out-of-band `MetricsRecorderInterface` sink (Prometheus, StatsD, logs) notified of every operation and connection
event. Independent of `cn=monitor`; either or both can be enabled.

**Default**: a no-op recorder

## SASL Options

------------------
#### setSaslMechanisms

The SASL mechanisms the server should support and advertise to clients via the `supportedSaslMechanisms` RootDSE attribute.
Use the constants defined on `ServerOptions` to specify mechanisms:

| Constant                                  | Mechanism             |
|-------------------------------------------|-----------------------|
| `ServerOptions::SASL_PLAIN`               | `PLAIN`               |
| `ServerOptions::SASL_EXTERNAL`            | `EXTERNAL`            |
| `ServerOptions::SASL_CRAM_MD5`            | `CRAM-MD5`            |
| `ServerOptions::SASL_SCRAM_SHA_1`         | `SCRAM-SHA-1`         |
| `ServerOptions::SASL_SCRAM_SHA_1_PLUS`    | `SCRAM-SHA-1-PLUS`    |
| `ServerOptions::SASL_SCRAM_SHA_224`       | `SCRAM-SHA-224`       |
| `ServerOptions::SASL_SCRAM_SHA_224_PLUS`  | `SCRAM-SHA-224-PLUS`  |
| `ServerOptions::SASL_SCRAM_SHA_256`       | `SCRAM-SHA-256`       |
| `ServerOptions::SASL_SCRAM_SHA_256_PLUS`  | `SCRAM-SHA-256-PLUS`  |
| `ServerOptions::SASL_SCRAM_SHA_384`       | `SCRAM-SHA-384`       |
| `ServerOptions::SASL_SCRAM_SHA_384_PLUS`  | `SCRAM-SHA-384-PLUS`  |
| `ServerOptions::SASL_SCRAM_SHA_512`       | `SCRAM-SHA-512`       |
| `ServerOptions::SASL_SCRAM_SHA_512_PLUS`  | `SCRAM-SHA-512-PLUS`  |
| `ServerOptions::SASL_SCRAM_SHA3_512`      | `SCRAM-SHA3-512`      |
| `ServerOptions::SASL_SCRAM_SHA3_512_PLUS` | `SCRAM-SHA3-512-PLUS` |

All mechanisms call `getSaslIdentity()` on `PasswordAuthenticatableInterface`. PLAIN accepts any hash scheme
supported by `PasswordHashService`. Challenge mechanisms (CRAM-MD5, SCRAM-*) require a plaintext or recoverable
password since the digest is computed server-side.

DIGEST-MD5 is not offered, as RFC 6331 moved it to Historic. Use `SASL_SCRAM_SHA_256` instead.

All mechanisms are handled through `PasswordAuthenticatableInterface` — no separate handler interface is required.
Configure authentication via `setPasswordAuthenticator()` or by implementing `PasswordAuthenticatableInterface`
on your backend. See [Authentication](General-Usage.md#authentication) for details.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer(
    (new ServerOptions)
        ->setSaslMechanisms(
            ServerOptions::SASL_PLAIN,
            ServerOptions::SASL_SCRAM_SHA_256,
        )
);
```

**Note**: The `PLAIN` mechanism transmits credentials in cleartext. It should only be enabled when the connection is
protected by TLS (via StartTLS or `setUseSsl`).

**Note**: The `EXTERNAL` mechanism authenticates from the verified TLS client certificate rather than `getSaslIdentity()`.
It requires a TLS connection **and** client-certificate validation (`setSslValidateCert(true)` with `setSslCaCert()`),
otherwise the bind is rejected. By default, the certificate subject DN is resolved via the identity resolver chain. You 
can customize the mapping with [setExternalCredentialMapper](#setexternalcredentialmapper).

See [SASL Authentication](General-Usage.md#sasl-authentication) for full usage details.

**Default**: `[]` (SASL disabled)

------------------
#### setExternalCredentialMapper

Customizes how a verified TLS client certificate is mapped to an identity for the `EXTERNAL` mechanism. The
mapper returns an `AuthzId` (a `dn:`/`u:` identity) that is resolved through the identity resolver chain, or `null` to
reject the certificate.

The default (`SubjectDnCredentialMapper`) reconstructs the certificate subject DN (X.509 order reversed to LDAP order)
and resolves it as a DN. Provide a custom mapper to instead map a SAN/UPN, rewrite the DN, or gate on the issuer:

```php
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\Backend\Auth\ExternalCredentialMapperInterface;
use FreeDSx\Socket\Tls\Certificate;

$mapper = new class implements ExternalCredentialMapperInterface {
    public function map(Certificate $certificate): ?AuthzId
    {
        // Resolve the entry by the certificate's subjectAltName via an attribute search.
        $san = $certificate->getSubjectAltName();

        return $san === null
            ? null
            : AuthzId::fromUsername($san);
    }
};

$options->setSaslMechanisms(ServerOptions::SASL_EXTERNAL)
    ->setExternalCredentialMapper($mapper);
```

A client may also send an authorization identity (`dn:`/`u:`) in the EXTERNAL credentials to act as a different
identity. This is only allowed when the certificate identity holds the proxied-authorization grant (RFC 4370).

**Default**: `null` (the certificate subject DN mapper)
