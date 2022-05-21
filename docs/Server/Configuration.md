LDAP Server Configuration
================

* [General Options](#general-options)
    * [ip](#ip)
    * [port](#port)
    * [unix_socket](#unix_socket)
    * [transport](#transport)
    * [logger](#logger)
    * [idle_timeout](#idle_timeout)
    * [require_authentication](#require_authentication)
    * [allow_anonymous](#allow_anonymous)
* [LDAP Protocol Handlers](#ldap-protocol-handlers)
   * [request_handler](#request_handler)
   * [rootdse_handler](#rootdse_handler)
   * [paging_handler](#paging_handler)
* [RootDSE Options](#rootdse-options)
    * [dse_naming_contexts](#dse_naming_contexts)
    * [dse_alt_server](#dse_alt_server)
    * [dse_vendor_name](#dse_vendor_name)
    * [dse_vendor_version](#dse_vendor_version)
* [SSL and TLS Options](#ssl-and-tls-options)
    * [ssl_cert](#ssl_cert)
    * [ssl_cert_key](#ssl_cert_key)
    * [ssl_cert_passphrase](#ssl_cert_passphrase)

The LDAP server is configured through an array of configuration values. The configuration is simply passed to the server
on construction:

```php
use FreeDSx\Ldap\LdapServer;

$ldap = new LdapServer([
    'dse_alt_server' => 'dc2.local',
    'port' => 33389,
]);
```

The following documents these various configuration options and how they impact the server.

## General Options

------------------
#### ip

The IP address to bind and listen to while the server is running. By default it will bind to `0.0.0.0`, which will listen
on all IP addresses of the machine.

**Default**: `0.0.0.0`

------------------
#### port

The port to bind to and accept client connections on. By default this is port 389. Since this port is underneath the
first 1024 ports, it will require administrative access when running the server. You can change this to something higher
than 1024 instead if needed.

**Default**: `389`

------------------
#### unix_socket

When using `unix` as the transport type, this is the full path to the socket file the client must interact with. 

**Default**: `/var/run/ldap.socket`

------------------
#### transport

The transport mechanism for the server to use. Use either:

* `tcp`
* `unix`

If using `unix` for the transport you can change set the `unix_socket` to a file path representing the unix socket the clients must connect to.

**Default**: `tcp`

------------------
#### logger

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
#### idle_timeout

Consider an idle client to timeout after this period of time (in seconds) and disconnect their LDAP session. If set to
-1, the client can idle indefinitely and not timeout the connection to the server.

**Default**: `600`

------------------
#### require_authentication

Whether or not authentication (bind) should be required before an operation is allowed.

**Note**: Certain LDAP operations implicitly do not require authentication: StartTLS, RootDSE requests, WhoAmI

**Default**: `true`

------------------
#### allow_anonymous

Whether or not anonymous binds should be allowed.

**Default**: `false`


## LDAP Protocol Handlers

The LDAP server works by being provided "handler" classes. These classes implement interfaces to handle specific LDAP
client requests and finish responses to them. You can either define a fully qualified class name for the handler in the 
option, or provide an instance of the class. There are also methods available on the server for setting instances of these
handlers (which will be detailed below).

------------------
#### request_handler

This should be a string class name or object instance that implements `FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface`. Server 
request operations are then passed to this class along with the request context.

This request handler is used for each client connection.

You can also set this handler after instantiating the server and before running it:

```php
use FreeDSx\Ldap\LdapServer;
use App\MySpecialRequestHandler;

$server = new LdapServer([
    'dse_alt_server' => 'dc2.local',
    'port' => 33389,
]);

$server->useRequestHandler(new MySpecialRequestHandler());
```

**Default**: `FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler`

#### rootdse_handler

This should be a fully qualified class name string or object instance that implements `FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface`. If this is defined,
the server will use it when responding to RootDSE requests from clients. If it is not defined, then the server will always
respond with a default RootDSE entry composed of values provided in the `dse_*` config options.

You can also set this handler after instantiating the server and before running it:

```php
use FreeDSx\Ldap\LdapServer;
use App\MySpecialRootDseHandler;

$server = new LdapServer([
    'dse_alt_server' => 'dc2.local',
    'port' => 33389,
]);

$server->useRootDseHandler(new MySpecialRootDseHandler());
```

**Default**: `null`

#### paging_handler

This should be a fully qualified class name string or object instance that implements `FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface`. If this is defined,
the server will use it when responding to client paged search requests. If it is not defined, then the server may
send an operation error to the client if it requested a paged search as critical. If the paged search was not marked as
critical, then the server will ignore the client paging control and send the search through the standard `request_handler` class.

You can also set this handler after instantiating the server and before running it:

```php
use FreeDSx\Ldap\LdapServer;
use App\MySpecialPagingHandler;

$server = new LdapServer([
    'dse_alt_server' => 'dc2.local',
    'port' => 33389,
]);

$server->usePagingHandler(new MySpecialPagingHandler());
```

**Default**: `null`

## RootDSE Options

------------------
#### dse_naming_contexts

The namingContexts attribute for the RootDSE. 

**Default**: `dc=FreeDSx,dc=local`

------------------
#### dse_alt_server

The altServer attribute for the RootDSE. These should be alternate servers to be used if this one becomes unavailable.

**Default**: `(null)`

------------------
#### dse_vendor_name

The vendorName attribute for the RootDSE.

**Default**: `FreeDSx`

------------------
#### dse_vendor_version

The vendorVersion attribute for the RootDSE.

**Default**: `(null)`

## SSL and TLS Options

------------------
#### ssl_cert

The server certificate to use for clients issuing StartTLS commands to encrypt their TCP session.

**Note**: If no certificate is provided clients will be unable to issue a StartTLS operation.

**Default**: `(null)`

------------------
#### ssl_cert_key

The server certificate private key. This can also be bundled with the certificate in the `ssl_cert` option.

**Default**: `(null)`

------------------
#### ssl_cert_passphrase

The passphrase needed for the server certificate's private key. 

**Default**: `(null)`

------------------
#### use_ssl

If set to true, and the transport is `tcp`, the server will use an SSL stream to bind to the IP address. This forces clients
to use an encrypted stream only for communication to the server.

**Note**: LDAP over SSL, commonly referred to as LDAPS, is not an official LDAP standard. Support is dependent on the client.

**Default**: `false`
