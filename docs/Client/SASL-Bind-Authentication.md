SASL Bind Authentication
================

* [Mechanisms](#mechanisms)
* [Options](#options)

SASL support is provided via the [FreeDSx SASL](https://github.com/FreeDSx/SASL) library. You can initiate a SASL bind
using the `bindSasl()` method on the client.

## Auto-selecting a Mechanism

Omit the mechanism to let the library select the strongest one advertised by the server:

```php
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Sasl\Options\DigestMD5Options;

$ldap = new LdapClient(
    (new ClientOptions)
        ->setServers(['ldap.example.com'])
        ->setBaseDn('dc=example,dc=local')
);

$ldap->bindSasl(
    (new DigestMD5Options)
        ->setUsername('user')
        ->setPassword('12345'),
);
```

## Specifying a Mechanism

Pass a `MechanismName` enum value as the second argument to target a specific mechanism:

```php
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\DigestMD5Options;

$ldap = new LdapClient(
    (new ClientOptions)
        ->setServers(['ldap.example.com'])
        ->setBaseDn('dc=example,dc=local')
);

$ldap->bindSasl(
    (new DigestMD5Options)
        ->setUsername('user')
        ->setPassword('12345'),
    MechanismName::DIGEST_MD5,
);
```

## Mechanisms

Each mechanism has its own options class from the `FreeDSx\Sasl\Options` namespace.

> **Prefer SCRAM for new deployments.** The `SCRAM-SHA-256` (or higher) family offers modern cryptographic
> guarantees and mutual authentication. `DIGEST-MD5` and `CRAM-MD5` are included for compatibility with
> legacy servers only and should be avoided where the server supports SCRAM.

### PLAIN

```php
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\PlainOptions;

$ldap->bindSasl(
    (new PlainOptions)
        ->setUsername('user')
        ->setPassword('12345'),
    MechanismName::PLAIN,
);
```

### CRAM-MD5

```php
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\CramMD5Options;

$ldap->bindSasl(
    (new CramMD5Options)
        ->setUsername('user')
        ->setPassword('12345'),
    MechanismName::CRAM_MD5,
);
```

### DIGEST-MD5

```php
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\DigestMD5Options;

$ldap->bindSasl(
    (new DigestMD5Options)
        ->setUsername('user')
        ->setPassword('12345'),
    MechanismName::DIGEST_MD5,
);
```

Use `setHost()` to override the host in the DIGEST-MD5 digest-uri. The integrity and privacy security layers are not
supported, and a bind that asks for one is refused. Use TLS to protect the connection instead.

### SCRAM

`SCRAM-*` refers to the SCRAM family: `SCRAM-SHA-1`, `SCRAM-SHA-256`, `SCRAM-SHA-384`, `SCRAM-SHA-512`,
`SCRAM-SHA3-512`, and their channel-binding (`-PLUS`) variants. `SCRAM-SHA-256` is recommended for new deployments.

```php
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\ScramOptions;

$ldap->bindSasl(
    (new ScramOptions)
        ->setUsername('user')
        ->setPassword('12345'),
    MechanismName::SCRAM_SHA256,
);
```

## Options

| Class             | Setter               | Mechanisms                  | Description                                            |
|-------------------|----------------------|-----------------------------|--------------------------------------------------------|
| `PlainOptions`    | `setUsername()`      | `PLAIN`                     | The authentication identity (username).                |
| `PlainOptions`    | `setPassword()`      | `PLAIN`                     | The password.                                          |
| `CramMD5Options`  | `setUsername()`      | `CRAM-MD5`                  | The username.                                          |
| `CramMD5Options`  | `setPassword()`      | `CRAM-MD5`                  | The password.                                          |
| `DigestMD5Options`| `setUsername()`      | `DIGEST-MD5`                | The username.                                          |
| `DigestMD5Options`| `setPassword()`      | `DIGEST-MD5`                | The password.                                          |
| `DigestMD5Options`| `setHost()`          | `DIGEST-MD5`                | Override the host in the digest-uri.                   |
| `ScramOptions`    | `setUsername()`      | `SCRAM-*`                   | The username.                                          |
| `ScramOptions`    | `setPassword()`      | `SCRAM-*`                   | The password.                                          |
