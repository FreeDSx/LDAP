LDAP Client Configuration
================

* [General Options](#general-options)
    * [base_dn](#base_dn)
    * [page_size](#page_size)
    * [port](#port)
    * [servers](#servers)
    * [timeout_connect](#timeout_connect)
    * [timeout_read](#timeout_read)
    * [version](#version)
* [SSL and TLS Options](#ssl-and-tls-options)
    * [use_ssl](#use_ssl)
    * [ssl_validate_cert](#ssl_validate_cert)
    * [ssl_ca_cert](#ssl_ca_cert)
    * [ssl_allow_self_signed](#ssl_allow_self_signed)

The LDAP client is configured through an array of configuration values. The configuration is simply passed to the client
on construction:

```php
use FreeDSx\Ldap\LdapClient;

$ldap = new LdapClient([
    'servers' => ['dc1', 'dc2', 'dc3'],
    'timeout_connect' => 1,
]);
```

The following documents these various configuration options and how they impact the client.

## General Options

------------------
#### base_dn

A default base DN to use when searching. This will be used if a base DN is not supplied explicitly in a search.

**Default**: `(null)`

------------------
#### page_size

A default page size to use for paging operations. This will be used if a page size is not explicitly passed on the
client's paging method.

**Default**: `1000`

------------------
#### port

The port to connect to on the LDAP server.

**Default**: `389`

------------------
#### servers

An array of LDAP servers. When connecting the servers are tried in order until one connects. 

**Default**: `[]`

------------------
#### timeout_connect

The timeout period (in seconds) when connecting to an LDAP server initially.

**Default**: `3`

------------------
#### timeout_read

The timeout period (in seconds) when reading data from a server.

**Default**: `15`

------------------
#### version

The LDAP version to use.

**Note**: This library was designed around version 3 only. Changing this may produce unexpected behavior.

**Default**: `3`

## SSL and TLS Options

------------------
#### use_ssl

If set to true, the client will use an SSL stream to connect to the server. This would mostly be used for servers running
over port 636 using SSL only. You still must change the port number if you choose this option.

**Note**: LDAP over SSL (port 636), commonly referred to as LDAPS, has been deprecated. You should use StartTLS instead. 

**Default**: `false`

------------------
#### ssl_validate_cert

If this is set to false then no LDAP server certificate validation is performed when connecting via StartTLS or SSL.
This can be useful for trouble shooting, but it is recommended to set the certificate with `ssl_ca_cert` and keep this
set to true.

**Default**: `true`

------------------
#### ssl_ca_cert

The full path to the trusted CA certificate for the LDAP server certificate. This is used for SSL certificate validation
when connecting over StartTLS or SSL. 

**Default**: `(null)`

------------------
#### ssl_allow_self_signed

Whether or not self-signed certificates are valid when LDAP server certificate validation is done.

**Default**: `false`
