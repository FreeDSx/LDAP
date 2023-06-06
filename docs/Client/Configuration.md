LDAP Client Configuration
================

* [General Options](#general-options)
    * [ClientOptions::setBaseDn](#setbasedn)
    * [ClientOptions::setPageSize](#setpagesize)
    * [ClientOptions::setTransport](#settransport)
    * [ClientOptions::setPort](#setport)
    * [ClientOptions::setServers](#setservers)
    * [ClientOptions::settimeoutConnect](#settimeoutconnect)
    * [ClientOptions::setTimeoutTead](#settimeoutread)
    * [ClientOptions::setVersion](#setversion)
    * [ClientOptions::setReferral](#setreferral)
    * [ClientOptions::setReferralLimit](#setreferrallimit)
    * [ClientOptions::setReferralChaser](#setreferralchaser)
* [SSL and TLS Options](#ssl-and-tls-options)
    * [ClientOptions::setUseSsl](#setusessl)
    * [ClientOptions::setSslValidateCert](#setsslvalidatecert)
    * [ClientOptions::setSslCaCert](#setsslcacert)
    * [ClientOptions::setSslAllowSelfSigned](#setsslallowselfsigned)

The LDAP client is configured through a `ClientOptions` object. The configuration object is passed to the client
on construction:

```php
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\ClientOptions;

$options = (new ClientOptions)
    ->setServers([
        'dc1',
        'dc2',
        'dc3',
    ])
    ->setTimeoutConnect(1)

$ldap = new LdapClient($options);
```

The following documents these various configuration option setter methods and how they impact the client.

## General Options

------------------
#### setBaseDn

A default base DN to use when searching. This will be used if a base DN is not supplied explicitly in a search.

**Default**: `(null)`

------------------
#### setPageSize

A default page size to use for paging operations. This will be used if a page size is not explicitly passed on the
client's paging method.

**Default**: `1000`

------------------
#### setTransport

The transport mechanism to connect to LDAP with. Use either:

* `tcp`
* `unix`

If using `unix` for the transport you should set the `servers` to a file representing the unix socket to connect to. ie: `/var/run/slapd/ldapi` (for OpenLDAP)

**Default**: `tcp`

------------------
#### setPort

The port to connect to on the LDAP server.

**Default**: `389`

------------------
#### setServers

An array of LDAP server(s) to connect to. When connecting the servers are tried in order until one 
connects. 

**Default**: `[]`

------------------
#### setTimeoutConnect

The timeout period (in seconds) when connecting to an LDAP server initially.

**Default**: `3`

------------------
#### setTimeoutRead

The timeout period (in seconds) when reading data from a server.

**Default**: `10`

------------------
#### setVersion

The LDAP version to use.

**Note**: This library was designed around version 3 only. Changing this may produce unexpected behavior.

**Default**: `3`

------------------
#### setReferral

The referral handling strategy to use. It must be one of:

* `throw`: When a referral is encountered it throws a ReferralException, which contains the referral object(s).
* `follow`: Referrals will be followed until a result is found or the `ClientOptions::setReferralLimit()` is reached.  

When you choose to follow referrals, it will bind to the referral destination using your previous bind request (if there
was one). If you need more control over the bind or what referrals are followed then use the `ClientOptions::setReferralChaser()` option.

**Default**: `throw`

------------------
#### setReferralLimit

The limit to the number of referrals to follow while trying to complete a request. Once this limit is reached an
OperationException with a code of referral is thrown. 

**Default**: 10

------------------
#### setReferralChaser

Use this with the referral option set to `follow`. Set this option to a class instance implementing `FreeDSx\Ldap\ReferralChaserInterface`.
You must implement two methods:

```php
public function chase(
    LdapMessageRequest $request,
    LdapUrl $referral,
    ?BindRequest $bind
) : ?BindRequest;

public function client(ClientOptions $options) : LdapClient;
```

Using this you can implement your own logic for whether to follow a referral and what credentials should be used.
You can skip a referral by throwing `FreeDSx\Ldap\Exception\SkipReferralException`. If you skip all referrals then a 
ReferralException will be thrown.

Using the `client($options)` method you can control how your LdapClient is constructed for the referral and perform any
needed logic beforehand, such as a StartTLS command.

**Default**: `null`

## SSL and TLS Options

------------------
#### setUseSsl

If set to true, the client will use an SSL stream to connect to the server. This would mostly be used for servers running
over port 636 using SSL only. You still must change the port number if you choose this option.

**Note**: LDAP over SSL (port 636), commonly referred to as LDAPS, is not an official LDAP standard. You should use the StartTLS method on the client instead.

**Default**: `false`

------------------
#### setSslValidateCert

If this is set to false then no LDAP server certificate validation is performed when connecting via StartTLS or SSL.
This can be useful for troubleshooting, but it is recommended to set the certificate with ``ClientOptions::setSslCaCert()`` and keep this
set to true.

**Default**: `true`

------------------
#### setSslCaCert

The full path to the trusted CA certificate for the LDAP server certificate. This is used for SSL certificate validation
when connecting over StartTLS or SSL. 

**Default**: `(null)`

------------------
#### setSslAllowSelfSigned

Whether self-signed certificates are valid when LDAP server certificate validation is done.

**Default**: `false`
