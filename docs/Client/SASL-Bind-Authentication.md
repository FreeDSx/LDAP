SASL Bind Authentication
================

* [Mechanisms](#mechanisms)
* [Options](#options)
    
SASL support is provided via the [FreeDSx SASL](https://github.com/FreeDSx/SASL) library. You can initiate a SASL bind
using the client methods.

An example of letting it auto-detect a mechanism:

```php
use FreeDSx\Ldap\LdapClient;

$ldap = new LdapClient([
    'servers' => 'ldap.example.com',
    'base_dn' => 'dc=example,dc=local'
]);

# Bind using SASL, let it automatically detect an available supported mechanism.
# The first parameter to bindSasl is an array of options for SASL to use.
$ldap->bindSasl([
    'username' => 'user',
    'password' => '12345',
]);
```

An example of specifying a mechanism:

```php
use FreeDSx\Ldap\LdapClient;

$ldap = new LdapClient([
    'servers' => 'ldap.example.com',
    'base_dn' => 'dc=example,dc=local'
]);

# Use the second parameter of bindSasl to specify a mechanism.
$ldap->bindSasl([
    'username' => 'user',
    'password' => '12345',
    # Also tell it to install an integrity security layer for further communications...
    'use_integrity' => true,
], 'DIGEST-MD5');
```

## Mechanisms

The following table details mechanisms / options that are recognized when doing a SASL bind:

|                  | `DIGEST-MD5`  | `CRAM-MD5` | `PLAIN` | `ANONYMOUS` |
| ---------------- | :-----------: | :--------: | :-----: | :---------: |
| `username`       | X             | X          | X       | X           |
| `password`       | X             | X          | X       |             |
| `use_integrity`  | X             |            |         |             |
| `trace`          |               |            |         | X           |
| `host`           | X             |            |         |             |

## Options

* `username`: The user to bind with.
* `password`: The password for the user during the bind.
* `use_integrity`: A boolean value for whether or not an integrity security layer should be used via SASL.
* `trace`: If defined during an anonymous bind, this string will be sent to the server for logging.
* `host`: If defined, this string value will be used as the host part of the digest-uri in DIGEST-MD5.
