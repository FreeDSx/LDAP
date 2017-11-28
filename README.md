# FreeDSx
FreeDSx is a pure PHP LDAP library. It has no requirement on the core PHP LDAP extension. This library currently implements
most client functionality described in [RFC 4511](https://tools.ietf.org/html/rfc4511) and some very limited LDAP server
functionality. It also implements some other client features from various RFCs:

* Paging Control Support ([RFC 2696](https://tools.ietf.org/html/rfc2696))
* VLV Control Support ([draft-ietf-ldapext-ldapv3-vlv-09](https://www.ietf.org/archive/id/draft-ietf-ldapext-ldapv3-vlv-09.txt))
* Server Side Sort Control ([RFC 2891](https://tools.ietf.org/html/rfc2891))
* Password Modify Request ([RFC 3062](https://tools.ietf.org/html/rfc3062))
* String Representation of Search Filters ([RFC 4515](https://tools.ietf.org/search/rfc4515))

It supports encryption of the LDAP connection through TLS via the OpenSSL extension if available.

# Getting Started

**Note**: This library is still under heavy development. Use with caution.

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
