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
* [LDAP Protocol Handlers](#ldap-protocol-handlers)
   * [ServerOptions:setRequestHandler](#setrequesthandler)
   * [ServerOptions:setRootDseHandler](#setrootdsehandler)
   * [ServerOptions:setPagingHandler](#setpaginghandler)
* [RootDSE Options](#rootdse-options)
    * [ServerOptions:setDseNamingContexts](#setdsenamingcontexts)
    * [ServerOptions:setDseAltServer](#setdsealtserver)
    * [ServerOptions:setDseVendorName](#setdsevendorname)
    * [ServerOptions:setDseVendorVersion](#setdsevendorversion)
* [SSL and TLS Options](#ssl-and-tls-options)
    * [ServerOptions:setSslCert](#setsslcert)
    * [ServerOptions:setSslCertKey](#setsslcertkey)
    * [ServerOptions:setSslCertPassphrase](#setsslcertpassphrase)

The LDAP server is configured through aa `ServerOptions` object. The configuration object is passed to the server
on construction:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$options = (new ServerOptions)
  ->setDseAlServer('dc2.local')
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


## LDAP Protocol Handlers

The LDAP server works by being provided "handler" classes. These classes implement interfaces to handle specific LDAP
client requests and finish responses to them. You can either define a fully qualified class name for the handler in the 
option, or provide an instance of the class. There are also methods available on the server for setting instances of these
handlers (which will be detailed below).

------------------
#### setRequestHandler

This should be an object instance that implements `FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface`. Server 
request operations are then passed to this class along with the request context.

This request handler is used for each client connection.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use App\MySpecialRequestHandler;

$server = new LdapServer(
    (new ServerOptions)
        ->setRequestHandler(new MySpecialRequestHandler())
);
```

**Default**: `FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler`

#### setRootDseHandler

This should be an object instance that implements `FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface`. If this is defined,
the server will use it when responding to RootDSE requests from clients. If it is not defined, then the server will always
respond with a default RootDSE entry composed of values provided in the `ServerOptions::getDse*()` config options.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use App\MySpecialRootDseHandler;

$server = new LdapServer(
    (new ServerOptions)
        ->setRootDseHandler(new MySpecialRootDseHandler())
);
```

**Default**: `null`

#### setPagingHandler

This should be an object instance that implements `FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface`. If this is defined,
the server will use it when responding to client paged search requests. If it is not defined, then the server may
send an operation error to the client if it requested a paged search as critical. If the paged search was not marked as
critical, then the server will ignore the client paging control and send the search through the standard `ServerOptions::getRequestHandler()` class instance.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use App\MySpecialPagingHandler;

$server = new LdapServer(
    (new ServerOptions)
        ->setPagingHandler(new MySpecialPagingHandler())
);
```

**Default**: `null`

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
