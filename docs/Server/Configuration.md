LDAP Server Configuration
================

* [General Options](#general-options)
    * [ServerOptions:setIp](#setip)
    * [ServerOptions:setPort](#setport)
    * [ServerOptions:setUnixSocket](#setunixsocket)
    * [ServerOptions:setTransport](#settransport)
    * [ServerOptions:setLogger](#setlogger)
    * [ServerOptions:setEventLogPolicy](#seteventlogpolicy)
    * [ServerOptions:setIdleTimeout](#setidletimeout)
    * [ServerOptions:setRequireAuthentication](#setrequireauthentication)
    * [ServerOptions:setAllowAnonymous](#setallowanonymous)
    * [ServerOptions:setSocketAcceptTimeout](#setsocketaccepttimeout)
* [Access Control](#access-control)
    * [ServerOptions:setAclRules](#setaclrules)
    * [ServerOptions:setAccessControl](#setaccesscontrol)
* [Backend](#backend)
    * [ServerOptions:setStorageConfig](#setstorageconfig)
    * [ServerOptions:setPasswordAuthenticator](#setpasswordauthenticator)
    * [ServerOptions:setIdentityResolver](#setidentityresolver)
* [Schema](#schema)
    * [ServerOptions:setSchemaValidationMode](#setschemavalidationmode)
    * [ServerOptions:setSchema](#setschema)
* [RootDSE Options](#rootdse-options)
    * [ServerOptions:setDseAltServer](#setdsealtserver)
    * [ServerOptions:setDseVendorName](#setdsevendorname)
    * [ServerOptions:setDseVendorVersion](#setdsevendorversion)
* [SSL and TLS Options](#ssl-and-tls-options)
    * [ServerOptions:setSslCert](#setsslcert)
    * [ServerOptions:setSslCertKey](#setsslcertkey)
    * [ServerOptions:setSslCertPassphrase](#setsslcertpassphrase)
    * [ServerOptions:setMinTlsVersion](#setmintlsversion)
    * [ServerOptions:setSslCiphers](#setsslciphers)
    * [ServerOptions:setSslValidateCert](#setsslvalidatecert)
    * [ServerOptions:setSslAllowSelfSigned](#setsslallowselfsigned)
    * [ServerOptions:setSslCaCert](#setsslcacert)
* [Search Limits](#search-limits)
    * [ServerOptions:setMaxSearchSize](#setmaxsearchsize)
    * [ServerOptions:setMaxSearchTimeLimit](#setmaxsearchtimelimit)
    * [ServerOptions:setMaxSearchPageSize](#setmaxsearchpagesize)
    * [ServerOptions:setMaxSearchLookthrough](#setmaxsearchlookthrough)
    * [ServerOptions:setMaxSearchPagedLookthrough](#setmaxsearchpagedlookthrough)
    * [ServerOptions:setSearchLimitRules](#setsearchlimitrules)
* [Directory Synchronization](#directory-synchronization)
    * [ServerOptions:setSyncEnabled](#setsyncenabled)
    * [ServerOptions:setChangeJournalConfig](#setchangejournalconfig)
* [Read-Only Replica](#read-only-replica)
    * [ServerOptions:setReplicaConfig](#setreplicaconfig)
    * [ReplicaConfig:setBind](#setbind)
    * [ReplicaConfig:setUseStartTls](#setusestarttls)
    * [ReplicaConfig:setReferWrites](#setreferwrites)
    * [ReplicaConfig:setFilter](#setfilter)
    * [ReplicaConfig:setReconnectBackoff](#setreconnectbackoff)
* [SASL Options](#sasl-options)
    * [ServerOptions:setSaslMechanisms](#setsaslmechanisms)
    * [ServerOptions:setExternalCredentialMapper](#setexternalcredentialmapper)

The LDAP server is configured through a `ServerOptions` object. The configuration object is passed to the server
on construction:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$options = (new ServerOptions)
  ->setDseAltServer('dc2.local')
  ->setPort(33389);

$ldap = new LdapServer($options);
```

The following documents these various configuration options and how they impact the server.

## General Options

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
on `session.disconnect_notice` events are also opt-in via `withExceptionTraces()`.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;

$options = (new ServerOptions())
    ->setEventLogPolicy(EventLogPolicy::default()->withAuditTrail());
```

See [Server Logging](Logging.md) for the full event catalog, the context-key reference, and
the policy API.

**Default**: `EventLogPolicy::default()`

------------------
#### setIdleTimeout

Consider an idle client to timeout after this period of time (in seconds) and disconnect their LDAP session. If set to
-1, the client can idle indefinitely and not timeout the connection to the server.

**Default**: `600`

------------------
#### setWriteTimeout

Disconnect a client whose response send makes no progress for this many seconds (a reader that has stopped draining).
Set to `0` to disable.

**Default**: `600`

------------------
#### setRequireAuthentication

Whether authentication (bind) should be required before an operation is allowed.

**Note**: Certain LDAP operations implicitly do not require authentication: StartTLS, RootDSE requests, WhoAmI

**Default**: `true`

------------------
#### setAllowAnonymous

Whether anonymous binds should be allowed.

**Default**: `false`

------------------
#### setSocketAcceptTimeout

The number of seconds (fractional) to wait for a new client connection before re-checking server state. Lower values
make the server more responsive to shutdown signals and connection-limit changes at the cost of slightly more CPU usage
in the accept loop.

**Default**: `0.5`


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
    (new ServerOptions())
        ->setAclRules(
            (new AclRules())->withOperationRules(
                OperationRule::allow(Subject::authenticated()),
                OperationRule::deny(Subject::anyone()),
            ),
        )
);
```

See [Access Control](Access-Control.md) for rule evaluation, subject/target matchers, attribute rules, and the
control-rule grants for privileged controls (e.g. Relax Rules).

**Default**: no rules — `SimpleAccessControl` denies anonymous operations and allows authenticated ones.

------------------
#### setAccessControl

Provide a fully custom `FreeDSx\Ldap\Server\AccessControl\AccessControlInterface` implementation, used instead of the
rule engine. Prefer `setAclRules()` unless the built-in rules are insufficient.

**Default**: `SimpleAccessControl`.

------------------
#### setPrivilegedControls

Control OIDs that an identity may use only when it holds an explicit `ControlRule` grant for that control. A request
attaching a privileged control without such a grant is denied. Controls not in this list need no grant. This replaces
the list, so include any defaults you want to keep.

```php
use FreeDSx\Ldap\Control\Control;

$options->setPrivilegedControls(
    Control::OID_RELAX_RULES,    // the default
    Control::OID_SUBTREE_DELETE, // also gate Tree-Delete behind a grant
);
```

See [Access Control](Access-Control.md) for control-rule grants.

**Default**: `[Control::OID_RELAX_RULES]` (Relax Rules).

## Backend

The LDAP server handles directory data through `WritableStorageBackend`, which applies LDAP semantics over the
storage built from the configured backend config.

------------------
#### setStorageConfig

Storage is configured on `ServerOptions` via `setStorageConfig()` or by passing a config to the `ServerOptions`
constructor. Choose one of the built-in backend configs: `InMemoryStorageConfig`, `JsonStorageConfig`, or `PdoConfig`
(SQLite or MySQL). All directory operations (search, authenticate, and optionally write) are dispatched to the
resulting storage.

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

$server = new LdapServer(new ServerOptions(PdoConfig::forSqlite('/var/lib/myapp/ldap.sqlite')));
```

When no config is given the server uses a transient in-memory backend. That default is for testing only. Supply a
persistent config such as `PdoConfig::forSqlite()` in production.

The bundled SQLite and MySQL backends create their tables automatically on first connect. For managing that schema
yourself, see [Database Schema](Database-Schema.md).

------------------
#### setPasswordAuthenticator

This should be an object instance that implements `FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface`.
It handles all password-based bind authentication through two methods:

* `authenticate(string $name, string $password): AuthenticatedTokenInterface` — called for simple binds
* `getSaslIdentity(string $username, MechanismName $mechanism): ?SaslIdentity` — called for all SASL mechanisms
  (PLAIN, CRAM-MD5, DIGEST-MD5, SCRAM-*). Returns the stored password and resolved DN, or `null` to reject.

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
        // Challenge mechanisms (CRAM-MD5, DIGEST-MD5, SCRAM-*) require a plaintext
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

**Note**: Challenge-based mechanisms (CRAM-MD5, DIGEST-MD5, SCRAM-*) require `getSaslIdentity()` to return a
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

## Schema

These configure schema validation for storage-backend writes. For full documentation, see
[Schema Validation](Schema.md).

------------------
#### setSchemaValidationMode

How `add`/`modify` writes are validated:

* `Strict` rejects violations
* `Lenient` logs them but allows the write
* `Off` skips validation

See [Validation Mode](Schema.md#validation-mode).

**Default**: `SchemaValidationMode::Strict`

------------------
#### setSchema

Replaces the active schema used for validation and operational attributes. See
[Custom Schema](Schema.md#custom-schema).

**Default**: `StandardSchemaProvider::buildCore()`

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

## SSL and TLS Options

------------------
#### setSslCert

The server certificate to use for clients issuing StartTLS commands to encrypt their TCP session.

**Note**: If no certificate is provided clients will be unable to issue a StartTLS operation.

**Default**: `(null)`

------------------
#### setSslCertKey

The server certificate private key. This can also be bundled with the certificate in the `ServerOptions::setSslCert` option.

**Default**: `(null)`

------------------
#### setSslCertPassphrase

The passphrase needed for the server certificate's private key.

**Default**: `(null)`

------------------
#### setUseSsl

If set to true, and the transport is `tcp`, the server will use an SSL stream to bind to the IP address. This forces clients
to use an encrypted stream only for communication to the server.

**Note**: LDAP over SSL, commonly referred to as LDAPS, is not an official LDAP standard. Support is dependent on the client / server specific implementations.

**Default**: `false`

------------------
#### setMinTlsVersion

The minimum TLS protocol version the server will negotiate for StartTLS and LDAPS sessions. Provide a
`FreeDSx\Ldap\Server\TlsVersion` case (`Tls1_0`, `Tls1_1`, `Tls1_2`, `Tls1_3`); the server accepts that version and any
higher one. The default rejects the deprecated TLS 1.0 and 1.1 (RFC 8996); lower it explicitly only for legacy clients.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Server\TlsVersion;

$options = (new ServerOptions())
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

## Search Limits

Server-side caps applied independently of what the client requests. When both the client and server specify a limit, the
stricter value wins. A server value of `0` means no server-side cap.

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
(or sends `0` meaning "server decides"), this cap is applied.

**Default**: `1000`

------------------
#### setMaxSearchLookthrough

Maximum number of entries the server will examine while evaluating a search before returning an `ADMIN_LIMIT_EXCEEDED`
result code. Unlike the size limit (entries returned), this caps entries inspected, so it bounds an unindexed filter that
scans many entries to return few. Raise it above the largest legitimate subtree a client may scan, or set `0` to disable.

**Default**: `5000`

> It applies only to filters evaluated in PHP (array/JSON backends, and SQL backends when the filter cannot be pushed to the
> index); indexed equality and prefix filters are bounded by the database and are not counted. Paged searches are subject to
> the lookthrough limit cumulatively across all pages (see `setMaxSearchPagedLookthrough` to set a separate cap for paging).

------------------
#### setMaxSearchPagedLookthrough

Set a lookthrough cap applied to paged searches, counted cumulatively across all pages. Paging is the standard way to retrieve
large result sets, so this lets you allow large paged enumerations without loosening the regular `setMaxSearchLookthrough`
for ordinary searches. A value of `0` falls back to the regular lookthrough limit.

**Default**: `0` (use the regular lookthrough limit)

------------------
#### setSearchLimitRules

Per-identity search limits: an ordered list of `(subject, limits)` rules, evaluated first-match-wins. The first rule whose
subject matches the bound identity supplies that request's limits; identities matching no rule get the global limits above.

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
#### setSyncEnabled

Whether the server records writes in a change journal and answers content-sync requests. The storage must support
journaling (all built-in storage does), and consumers must be granted the privileged sync control through access
control. See [Directory Synchronization](Replication.md).

**Default**: `false`

------------------
#### setChangeJournalConfig

The change journal configuration: the origin id stamped into sync cookies, and the retention policy that limits journal
growth. When the policy sets at least one limit, the journal is pruned on a cadence. See
[Retention](Replication.md#retention).

```php
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\RetentionPolicy;

$journalConfig = new ChangeJournalConfig(
    origin: new ReplicaId('dc1'),
    retention: new RetentionPolicy(maxRecords: 1_000_000),
);

$options->setChangeJournalConfig($journalConfig);
```

**Default**: origin `local` with no retention limits (the journal is not pruned).

## Read-Only Replica

Run the server as a read-only replica that mirrors a provider over RFC 4533. See
[Read-Only Replica](Replication.md#read-only-replica) for the full guide.

The `ReplicaConfig` is constructed with the provider's `ClientOptions` (servers, TLS, and the base DN of the subtree to
mirror) and, optionally, a `ReplicationCheckpointInterface` where the sync cookie is persisted. The checkpoint defaults
to in-memory; use `FileReplicationCheckpoint` in production so the replica resumes across restarts. The setters below
configure the rest.

------------------
#### setReplicaConfig

A `ServerOptions` setter that puts the server into read-only replica mode against the given `ReplicaConfig`. Client
writes are refused and a background daemon keeps the local storage in step with the provider.
`ServerOptions::forReplica($replicaConfig, $storageConfig)` is a shortcut that constructs the options with this
already set, taking the replica config and the backend storage config for the local mirror.

**Default**: `null` (the server is a normal read-write directory).

------------------
#### setBind

A `ReplicaConfig` setter for how the replica authenticates to the provider, as a `BindRequest` from `Operations::bind()`
(simple) or `Operations::bindSasl()` (SASL, including EXTERNAL for client-certificate auth).

**Default**: none

------------------
#### setUseStartTls

A `ReplicaConfig` setter for whether to issue StartTLS on the provider connection before binding. LDAPS is configured on
the primary `ClientOptions` instead.

**Default**: `false`

------------------
#### setReferWrites

A `ReplicaConfig` setter for whether a client write to the replica is referred to the provider (`true`) or rejected with
`unwillingToPerform` (`false`).

**Default**: `true`

------------------
#### setFilter

A `ReplicaConfig` setter for an optional filter restricting which entries are replicated.

**Default**: `null` (all in-scope entries).

------------------
#### setReconnectBackoff

A `ReplicaConfig` setter for the bounded exponential backoff applied between reconnect attempts to the provider.

**Default**: `new ReconnectBackoff()` (starts at 1s, doubling to a 30s ceiling).

## Monitoring

Opt-in observability. See [Server Monitoring](Monitoring.md) for the full guide, the `cn=monitor` attributes, and the
push-exporter contract.

------------------
#### setMonitorEnabled

Whether to serve the server-generated `cn=monitor` entry. When off, the route is not registered.

**Default**: `false`

------------------
#### setMonitorSnapshotPath

PCNTL only. Path to the JSON file the parent publishes for `cn=monitor` to read. When unset, a path under the system temp
directory keyed by listen port is used. Set this to avoid collisions when running several instances on one host.

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
| `ServerOptions::SASL_DIGEST_MD5`          | `DIGEST-MD5`          |
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
supported by `PasswordHashVerifier`; challenge mechanisms (CRAM-MD5, DIGEST-MD5, SCRAM-*) require a plaintext or
recoverable password since the digest is computed server-side.

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
use FreeDSx\Ldap\Server\Sasl\External\ExternalCredentialMapperInterface;
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
