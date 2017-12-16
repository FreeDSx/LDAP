# FreeDSx [![Build Status](https://travis-ci.org/FreeDSx/LDAP.svg?branch=master)](https://travis-ci.org/FreeDSx/LDAP) [![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/github/freedsx/ldap?branch=master&svg=true)](https://ci.appveyor.com/project/ChadSikorra/ldap)
FreeDSx is a pure PHP LDAP library. It has no requirement on the core PHP LDAP extension. This library currently implements
most client functionality described in [RFC 4511](https://tools.ietf.org/html/rfc4511) and some very limited LDAP server
functionality. It also implements some other client features from various RFCs:

* Paging Control Support ([RFC 2696](https://tools.ietf.org/html/rfc2696))
* VLV Control Support ([draft-ietf-ldapext-ldapv3-vlv-09](https://www.ietf.org/archive/id/draft-ietf-ldapext-ldapv3-vlv-09.txt))
* Server Side Sort Control ([RFC 2891](https://tools.ietf.org/html/rfc2891))
* Password Modify Request ([RFC 3062](https://tools.ietf.org/html/rfc3062))
* String Representation of Search Filters ([RFC 4515](https://tools.ietf.org/search/rfc4515))

It supports encryption of the LDAP connection through TLS via the OpenSSL extension if available.

# Documentation

* [LDAP Client](/docs/Client)
  * [Configuration](/docs/Client/Configuration.md)
  * [General Usage](/docs/Client/General-Usage.md)
  * [Operations](/docs/Client/Operations.md)
  * [Searching and Filters](/docs/Client/Searching-and-Filters.md)
* [LDAP Server](/docs/Server)
  * [Configuration](/docs/Server/Configuration.md)
  * [General Usage](/docs/Server/General-Usage.md)

# Getting Started

Install via composer:

```bash
composer require freedsx/ldap
```

Use the LdapClient class and the helper classes:

```php
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

$ldap = new LdapClient([
    # Servers are tried in order until one connects
    'servers' => ['dc1', 'dc2'],
    # The base_dn is used as the default for searches
    'base_dn' => 'dc=example,dc=local'
]);

# Bind to LDAP with a specific user.
$ldap->bind('user@example.local', '12345');

# Build up a LDAP filter using the helper methods
$filter = Filters::and(
    Filters::equal('objectClass', 'user'),
    Filters::startsWith('cn', 'S'),
    # Add a filter object based off a raw string filter...
    Filters::raw('(telephoneNumber=*)')
);
# Create a search operation to be used based on the above filter
$search = Operations::search($filter, 'cn');

# Create a paged search, 100 results at a time
$paging = $ldap->paging($search, 100);

while ($paging->hasEntries()) {
    $entries = $paging->getEntries();
    var_dump(count($entries));
    
    foreach ($entries as $entry) {
        echo "Entry: ".$entry->getDn().PHP_EOL;
    }
}
```