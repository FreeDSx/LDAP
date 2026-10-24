# FreeDSx LDAP ![](https://github.com/FreeDSx/LDAP/workflows/Analysis/badge.svg) ![](https://github.com/FreeDSx/LDAP/workflows/Build/badge.svg) [![codecov](https://codecov.io/gh/FreeDSx/LDAP/branch/main/graph/badge.svg)](https://codecov.io/gh/FreeDSx/LDAP)
FreeDSx LDAP is a pure PHP LDAP client and server library. It has no requirement on the core PHP LDAP extension. This library
implements the client and server sides of the LDAPv3 technical specification ([RFC 4510](https://datatracker.ietf.org/doc/rfc4510/))
(deviations are noted in [Conformance](/docs/Server/Conformance.md)). It also implements other features from
various RFCs and drafts:

| Feature               | RFC / Specification                                                                                           |  Client  |            Server            |
|-----------------------|---------------------------------------------------------------------------------------------------------------|:--------:|:----------------------------:|
| Paging                | [RFC 2696](https://datatracker.ietf.org/doc/rfc2696/)                                                         |    ✓     |              ✓               |
| Server Side Sort      | [RFC 2891](https://datatracker.ietf.org/doc/rfc2891/)                                                         |    ✓     |              ✓               |
| Virtual List View     | [draft-ietf-ldapext-ldapv3-vlv-09](https://www.ietf.org/archive/id/draft-ietf-ldapext-ldapv3-vlv-09.txt)      |    ✓     |                              |
| Password Modify       | [RFC 3062](https://datatracker.ietf.org/doc/rfc3062/)                                                         |    ✓     |              ✓               |
| Cancel                | [RFC 3909](https://datatracker.ietf.org/doc/rfc3909/)                                                         |    ✓     |              ✓               |
| Who Am I?             | [RFC 4532](https://datatracker.ietf.org/doc/rfc4532/)                                                         |    ✓     |              ✓               |
| Assertion Control     | [RFC 4528](https://datatracker.ietf.org/doc/rfc4528/)                                                         |    ✓     |              ✓               |
| Pre / Post Read       | [RFC 4527](https://datatracker.ietf.org/doc/rfc4527/)                                                         |    ✓     |              ✓               |
| Proxied Authorization | [RFC 4370](https://datatracker.ietf.org/doc/rfc4370/)                                                         |    ✓     |              ✓               |
| Subentries            | [RFC 3672](https://datatracker.ietf.org/doc/rfc3672/)                                                         |    ✓     |              ✓               |
| Relax Rules           | [draft-zeilenga-ldap-relax](https://datatracker.ietf.org/doc/draft-zeilenga-ldap-relax/)                      |    ✓     |              ✓               |
| Subtree Delete        | [draft-armijo-ldap-treedelete](https://datatracker.ietf.org/doc/draft-armijo-ldap-treedelete/)                |    ✓     |              ✓               |
| Password Policy       | [draft-behera-ldap-password-policy-10](https://datatracker.ietf.org/doc/draft-behera-ldap-password-policy/)   |    ✓     |              ✓               |
| SASL Authentication   | [RFC 4422](https://datatracker.ietf.org/doc/rfc4422/) / [RFC 4513](https://datatracker.ietf.org/doc/rfc4513/) |    ✓     |    ✓ (no integrity layer)    |
| SyncRepl              | [RFC 4533](https://datatracker.ietf.org/doc/rfc4533/)                                                         | Consumer | Provider + read-only replica |
| DirSync               | [draft-armijo-ldap-dirsync-01](https://www.ietf.org/archive/id/draft-armijo-ldap-dirsync-01.txt)              |    ✓     |                              |

# Documentation

**Note**: If you were previously using a version prior to `1.X`, see the [upgrade doc](UPGRADE-1.0.md) for important changes.

* [LDAP Client](/docs/Client)
  * [Configuration](/docs/Client/Configuration.md)
  * [SASL Bind Authentication](/docs/Client/SASL-Bind-Authentication.md)
  * [General Usage](/docs/Client/General-Usage.md)
  * [Entries](/docs/Client/Entries.md)
  * [Operations](/docs/Client/Operations.md)
  * [Controls](/docs/Client/Controls.md)
  * [Searching and Filters](/docs/Client/Searching-and-Filters.md)
  * [Range Retrieval](/docs/Client/Range-Retrieval.md)
  * [DirSync](/docs/Client/DirSync.md)
  * [SyncRepl](/docs/Client/SyncRepl.md)
* [LDAP Server](/docs/Server)
  * [Configuration](/docs/Server/Configuration.md)
  * [General Usage](/docs/Server/General-Usage.md)
  * [Proxy Server](/docs/Server/General-Usage.md#creating-a-proxy-server)
  * [LDIF Data](/docs/Server/General-Usage.md#ldif-data)
  * [Schema](/docs/Server/Schema.md)
  * [Logging](/docs/Server/Logging.md)
  * [Monitoring](/docs/Server/Monitoring.md)
  * [Access Control](/docs/Server/Access-Control.md)
  * [Password Policy](/docs/Server/Password-Policy.md)
  * [Directory Synchronization](/docs/Server/Replication.md)
  * [Database Schema](/docs/Server/Database-Schema.md)
  * [Conformance](/docs/Server/Conformance.md)

# Requirements

PHP 8.2 or newer is required. The `openssl` extension is optional and enables TLS and some SASL mechanisms.

The server also needs one runner and one storage backend, each with its own requirements:

| Component              | Requires                                                           |
|------------------------|--------------------------------------------------------------------|
| PCNTL runner (default) | `pcntl` and `posix` extensions (not available on Windows)          |
| Swoole runner          | `swoole` extension                                                 |
| SQLite storage         | `pdo_sqlite` and `mbstring` extensions                             |
| MySQL storage          | `pdo_mysql` and `mbstring` extensions, MySQL 8.0+ or MariaDB 10.6+ |
| In-memory storage      | The Swoole runner                                                  |

For Unicode case folding and normalization in string matching (RFC 4518), load the `mbstring` and `intl` extensions, or
install `symfony/polyfill-mbstring` and `symfony/polyfill-intl-normalizer`.

# Getting Started

Install via [composer](https://getcomposer.org/download/):

```bash
composer require freedsx/ldap
```

## Client

Use the LdapClient class and the helper classes:

```php
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Search\Filters;

$ldap = new LdapClient(
    (new ClientOptions)
        # Servers are tried in order until one connects
        ->setServers(['dc1', 'dc2'])
        # The base_dn is used as the default for searches
        ->setBaseDn('dc=example,dc=local')
);

# Encrypt the connection prior to binding
$ldap->startTls();

# Bind to LDAP with a specific user.
$ldap->bind(
    username: 'user@example.local',
    password: '12345'
);

# Use the query builder to construct and execute a paged search, 100 results at a time
$paging = $ldap->query()
    ->select('cn')
    ->andWhere(Filters::equal('objectClass', 'user'))
    ->andWhere(Filters::startsWith('cn', 'S'))
    ->andWhere(Filters::raw('(telephoneNumber=*)'))
    ->paging(100);

while ($paging->hasEntries()) {
    $entries = $paging->getEntries();

    var_dump(count($entries));

    foreach ($entries as $entry) {
        echo "Entry: " . $entry->getDn() . PHP_EOL;
    }
}
```

See [Operations](/docs/Client/Operations.md) for creating, reading, updating and deleting entries.

## Server

Use the LdapServer class with a storage backend. This seeds a SQLite database with a base entry and an admin user:

```php
use FreeDSx\Ldap\LdapServer;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Server\Backend\Storage\Import\SeedOptions;
use FreeDSx\Ldap\Server\Config\NetworkConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\ServerOptions;

$passwordHash = '{BCRYPT}' . password_hash(
    'secret',
    PASSWORD_BCRYPT,
);

$server = new LdapServer(new ServerOptions(
    # Entries are persisted to a SQLite file
    PdoConfig::forSqlite('/var/lib/myapp/ldap.sqlite'),
    # Listen on a custom port (defaults to 389)
    NetworkConfig::withPort(3389),
));

# Entries that already exist are left untouched
$server->seed(
    new StringLdifLoader(<<<LDIF
        dn: dc=example,dc=com
        objectClass: domain
        dc: example

        dn: cn=admin,dc=example,dc=com
        objectClass: person
        cn: admin
        sn: admin
        userPassword: {$passwordHash}
        LDIF),
    new SeedOptions(skipExisting: true),
);

# Clients can now bind as cn=admin,dc=example,dc=com with the password "secret"
$server->run();
```
