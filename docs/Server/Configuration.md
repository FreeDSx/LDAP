LDAP Server Configuration
================

* [General Options](#general-options)
    * [ServerOptions:setIp](#setip)
    * [ServerOptions:setPort](#setport)
    * [ServerOptions:setUnixSocket](#setunixsocket)
    * [ServerOptions:setTransport](#settransport)
    * [ServerOptions:setLogger](#setlogger)
    * [ServerOptions:setIdleTimeout](#setidletimeout)
    * [ServerOptions:setRequireAuthentication](#setrequireauthentication)
    * [ServerOptions:setAllowAnonymous](#setallowanonymous)
    * [ServerOptions:setSocketAcceptTimeout](#setsocketaccepttimeout)
* [Backend](#backend)
    * [ServerOptions:setBackend](#setbackend)
    * [ServerOptions:setFilterEvaluator](#setfilterevaluator)
    * [ServerOptions:setRootDseHandler](#setrootdsehandler)
    * [ServerOptions:setPasswordAuthenticator](#setpasswordauthenticator)
    * [ServerOptions:setBindNameResolver](#setbindnameresolver)
* [RootDSE Options](#rootdse-options)
    * [ServerOptions:setDseNamingContexts](#setdsenamingcontexts)
    * [ServerOptions:setDseAltServer](#setdsealtserver)
    * [ServerOptions:setDseVendorName](#setdsevendorname)
    * [ServerOptions:setDseVendorVersion](#setdsevendorversion)
* [SSL and TLS Options](#ssl-and-tls-options)
    * [ServerOptions:setSslCert](#setsslcert)
    * [ServerOptions:setSslCertKey](#setsslcertkey)
    * [ServerOptions:setSslCertPassphrase](#setsslcertpassphrase)
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

Specify a PSR-3 compatible logging instance to use. This will log various server events and errors.

You can also set the logger after instantiating the server and before running it:

```php
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer();

// instantiate some logger class...

$server->useLogger($logger);
```

**Default**: `null`

------------------
#### setIdleTimeout

Consider an idle client to timeout after this period of time (in seconds) and disconnect their LDAP session. If set to
-1, the client can idle indefinitely and not timeout the connection to the server.

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

**Default**: `null` (a no-op backend that returns errors for all operations)

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
It handles all password-based bind authentication — both simple binds and SASL mechanisms — through two methods:

* `verifyPassword(string $name, string $password): bool` — called for simple binds and SASL PLAIN
* `getPassword(string $username, string $mechanism): ?string` — called for challenge-based SASL mechanisms
  (CRAM-MD5, DIGEST-MD5, SCRAM-*) that need a server-side credential to compute a digest

The server resolves an authenticator in this order:

1. An explicit instance set via `setPasswordAuthenticator()`
2. The backend, if it implements `PasswordAuthenticatableInterface`
3. A built-in `PasswordAuthenticator` that resolves the bind name to an entry via the configured
   `BindNameResolverInterface` and verifies the entry's `userPassword` attribute

Use this option when you need to delegate authentication to an external system (a database, an upstream LDAP server,
an identity provider, etc.) without implementing the storage backend interface:

```php
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;

class ExternalAuthenticator implements PasswordAuthenticatableInterface
{
    public function verifyPassword(string $name, #[\SensitiveParameter] string $password): bool
    {
        // delegate to your auth system
    }

    public function getPassword(string $username, string $mechanism): ?string
    {
        // return plaintext password for SASL challenge mechanisms,
        // or null to disable challenge SASL for this user
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

**Note**: Challenge-based SASL mechanisms (CRAM-MD5, DIGEST-MD5, SCRAM-*) require `getPassword()` to return a
plaintext (or recoverable) credential. If `getPassword()` returns `null`, the mechanism will fail for that user.

**Default**: `null` (resolved automatically as described above)

------------------
#### setBindNameResolver

This should be an object instance that implements `FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface`.
It translates a raw LDAP bind name into an `Entry` so the built-in `PasswordAuthenticator` can locate and verify credentials.

The default resolver (`DnBindNameResolver`) treats the bind name as a literal DN and delegates to `LdapBackendInterface::get()`.
Supply a custom resolver when clients bind with something other than a full DN — for example, a bare username or an email address:

```php
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Entry\Entry;

class UidBindNameResolver implements BindNameResolverInterface
{
    public function resolve(
        string $name,
        LdapBackendInterface $backend
    ): ?Entry {
        // Search for an entry whose uid attribute matches the bind name
        // ...
    }
}
```

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer(
    (new ServerOptions)
        ->setBackend(new MyDirectoryBackend())
        ->setBindNameResolver(new UidBindNameResolver())
);
```

**Note**: This option is only used when the built-in `PasswordAuthenticator` is active. If you provide a fully custom
authenticator via `setPasswordAuthenticator()`, name resolution is entirely your responsibility and this option has no effect.

**Default**: `null` (`DnBindNameResolver` is used, treating the bind name as a literal DN)

## RootDSE Options

------------------
#### setDseNamingContexts

The namingContexts attribute for the RootDSE as an array of strings.

**Default**: `['dc=FreeDSx,dc=local']`

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

## SASL Options

------------------
#### setSaslMechanisms

The SASL mechanisms the server should support and advertise to clients via the `supportedSaslMechanisms` RootDSE attribute.
Use the constants defined on `ServerOptions` to specify mechanisms:

| Constant                                  | Mechanism             | Auth method called on `PasswordAuthenticatableInterface` |
|-------------------------------------------|-----------------------|----------------------------------------------------------|
| `ServerOptions::SASL_PLAIN`               | `PLAIN`               | `verifyPassword()`                                       |
| `ServerOptions::SASL_CRAM_MD5`            | `CRAM-MD5`            | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_DIGEST_MD5`          | `DIGEST-MD5`          | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_1`         | `SCRAM-SHA-1`         | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_1_PLUS`    | `SCRAM-SHA-1-PLUS`    | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_224`       | `SCRAM-SHA-224`       | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_224_PLUS`  | `SCRAM-SHA-224-PLUS`  | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_256`       | `SCRAM-SHA-256`       | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_256_PLUS`  | `SCRAM-SHA-256-PLUS`  | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_384`       | `SCRAM-SHA-384`       | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_384_PLUS`  | `SCRAM-SHA-384-PLUS`  | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_512`       | `SCRAM-SHA-512`       | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA_512_PLUS`  | `SCRAM-SHA-512-PLUS`  | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA3_512`      | `SCRAM-SHA3-512`      | `getPassword()` (plaintext credential required)          |
| `ServerOptions::SASL_SCRAM_SHA3_512_PLUS` | `SCRAM-SHA3-512-PLUS` | `getPassword()` (plaintext credential required)          |

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
