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
    * [ServerOptions:setBackend](#setbackend)
    * [ServerOptions:setFilterEvaluator](#setfilterevaluator)
    * [ServerOptions:setRootDseHandler](#setrootdsehandler)
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
* [Search Limits](#search-limits)
    * [ServerOptions:setMaxSearchSize](#setmaxsearchsize)
    * [ServerOptions:setMaxSearchTimeLimit](#setmaxsearchtimelimit)
    * [ServerOptions:setMaxSearchPageSize](#setmaxsearchpagesize)
* [SASL Options](#sasl-options)
    * [ServerOptions:setSaslMechanisms](#setsaslmechanisms)

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

You can also set the logger after instantiating the server and before running it:

```php
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer();

// instantiate some logger class...

$server->useLogger($logger);
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

**Note**: This applies to the PCNTL runner only.

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

## Backend

The LDAP server works by being provided a backend that implements `LdapBackendInterface` (or the writable extension
`WritableLdapBackendInterface`). The backend is responsible for handling directory data (search, authentication, and
optionally write operations). You can also plug in a custom filter evaluator or a custom RootDSE handler.

------------------
#### setBackend

This should be an object instance that implements `FreeDSx\Ldap\Server\Backend\LdapBackendInterface`. All directory
operations (search, authenticate, and optionally write) are dispatched to this backend. Paging is handled automatically — no separate paging handler is needed.

You can also use the fluent `useBackend()` method on `LdapServer` instead of setting it in `ServerOptions`:

```php
use FreeDSx\Ldap\LdapServer;
use App\MyDirectoryBackend;

$server = (new LdapServer())
    ->useBackend(new MyDirectoryBackend());
```

Or via `ServerOptions`:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use App\MyDirectoryBackend;

$server = new LdapServer(
    (new ServerOptions)
        ->setBackend(new MyDirectoryBackend())
);
```

**Default**: `null` (falls back to an empty in-memory backend: searches return no entries, writes are rejected with `unwillingToPerform`)

------------------
#### setFilterEvaluator

This should be an object instance that implements `FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface`. If provided,
the server uses it when evaluating LDAP search filters against candidate entries returned by the backend. The default
evaluator covers all standard LDAP filter types. A custom evaluator is useful when you need non-standard matching rules
(for example, bitwise matching rules for Active Directory compatibility).

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use App\MyFilterEvaluator;

$server = (new LdapServer())
    ->useFilterEvaluator(new MyFilterEvaluator());
```

**Default**: `FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluator`

------------------
#### setRootDseHandler

This should be an object instance that implements `FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface`. If
defined, the server calls it when responding to RootDSE requests from clients, passing the pre-built default entry so
the handler can inspect or augment it. If not defined, the server responds with a default RootDSE entry composed of
values from the `ServerOptions::getDse*()` configuration options.

When a backend is provided and implements `RootDseHandlerInterface`, it is used automatically — no separate
`setRootDseHandler()` call is needed.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use App\MyRootDseHandler;

$server = new LdapServer(
    (new ServerOptions)
        ->setRootDseHandler(new MyRootDseHandler())
);
```

**Default**: `null`

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

These configure schema validation for `useStorage()` writes. For full documentation, see
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

## SASL Options

------------------
#### setSaslMechanisms

The SASL mechanisms the server should support and advertise to clients via the `supportedSaslMechanisms` RootDSE attribute.
Use the constants defined on `ServerOptions` to specify mechanisms:

| Constant                                  | Mechanism             |
|-------------------------------------------|-----------------------|
| `ServerOptions::SASL_PLAIN`               | `PLAIN`               |
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

See [SASL Authentication](General-Usage.md#sasl-authentication) for full usage details.

**Default**: `[]` (SASL disabled)
