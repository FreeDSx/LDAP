General LDAP Server Usage
===================

* [Running the Server](#running-the-server)
* [Creating a Proxy Server](#creating-a-proxy-server)
* [Handling Client Requests](#handling-client-requests)
  * [Proxy Request Handler](#proxy-request-handler)
  * [Generic Request Handler](#generic-request-handler)
* [Handling the RootDSE](#handling-the-rootdse)
* [Handling Client Paging Requests](#handling-client-paging-requests)
* [StartTLS SSL Certificate Support](#starttls-ssl-certificate-support)
* [SASL Authentication](#sasl-authentication)
  * [PLAIN Mechanism](#plain-mechanism)
  * [Challenge-Based Mechanisms (CRAM-MD5, DIGEST-MD5, and SCRAM)](#challenge-based-mechanisms-cram-md5-digest-md5-and-scram)

The LdapServer class is used to run a LDAP server process that accepts client requests and sends back a response. It
defaults to using a forking method for client requests, which is only available on Linux.

The LDAP server has no entry database/schema persistence by itself. It is currently up to the implementor to determine 
how to create / update / delete / search for entries that are requested from the client. See the [Handling Client Requests](#handling-client-requests)
section for more details.

## Running The Server

In its most simple form you can run the LDAP server by constructing the class and calling the `run()` method. This will
bind to port 389 to accept clients from any IP on the server. It will use the GenericRequestHandler which by default 
rejects client requests for any operation. 

```php
use FreeDSx\Ldap\LdapServer;

$server = (new LdapServer())->run();
```

### Creating a Proxy Server

The LDAP server is capable of acting as a proxy between other LDAP servers through the use of the handlers. There is a
helper factory method defined on the LdapServer class that makes creating a proxy server very easy. However, it provides
no real extensibility if you aren't defining your own handlers.

The proxy server can be constructed as follows:

```php
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = LdapServer::makeProxy(
    // The LDAP server to proxy connections to...
    servers: 'ldap.example.com',
    // Any additional LdapClient options for the proxy...
    clientOptions: new ClientOptions(),
    // Any additional LdapServer options. In this case, run over port 3389
    serverOptions: (new ServerOptions)->setPort(3389),
);

$server->run();
```

## Handling Client Requests

When the server receives a client request it will get sent to the request handler defined for the server. There are only
a few types of requests not sent to the request handler:

* WhoAmI
* StartTLS
* RootDSE
* Unbind

All other requests are sent to handler you define. The handler must implement `FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface`.
The interface has the following methods:

```php
    public function add(RequestContext $context, AddRequest $add);

    public function compare(RequestContext $context, CompareRequest $compare) : bool;
    
    public function delete(RequestContext $context, DeleteRequest $delete);

    public function extended(RequestContext $context, ExtendedRequest $extended);

    public function modify(RequestContext $context, ModifyRequest $modify);

    public function modifyDn(RequestContext $context, ModifyDnRequest $modifyDn);

    public function search(RequestContext $context, SearchRequest $search) : Entries;
    
    public function bind(string $username, string $password) : bool;
```

However, there is a generic request handler you can extend to implement only what you want. Or a proxy handler to forward
requests to a separate LDAP server.

### Proxy Request Handler

**Note**: If you just want to create an LDAP server that serves as a proxy, see the section on [creating a proxy server](#creating-a-proxy-server).

The proxy request handler simply forwards the LDAP request from the FreeDSx server to a different LDAP server, then sends
the response back to the client. You should extend the ProxyRequestHandler class and add your own client options to be
used.

1. Create your own class extending the ProxyRequestHandler:

```php
namespace Foo;

use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;

class LdapProxyHandler extends ProxyRequestHandler
{
    /**
     * Set the options for the LdapClient in the constructor.
     */
    public function __construct()
    {
        parent::__construct(
            (new ClientOptions)
                ->setServers([
                    'dc1.domain.local',
                    'dc2.domain.local',
                 ])
                 ->setBaseDn('dc=domain,dc=local')
        );
    }
}
```

2. Create the server and run it with the request handler above: 

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use Foo\LdapProxyHandler;

$server = new LdapServer(
    (new ServerOptions)->setRequestHandler(new LdapProxyHandler())
);
$server->run();
```

### Generic Request Handler

The generic request handler implements the needed RequestHandlerInterface, but rejects all request types by default. You
should extend this class and override the methods for the requests you want to support:

1. Create your own class extending the GenericRequestHandler:

```php
namespace Foo;

use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;

class LdapRequestHandler extends GenericRequestHandler
{
    /**
     * @var array
     */
    protected $users = [
        'user' => '12345',
    ];

    /**
     * Validates the username/password of a simple bind request
     *
     * @param string $username
     * @param string $password
     * @return bool
     */
    public function bind(string $username, string $password): bool
    {
        return isset($this->users[$username]) && $this->users[$username] === $password;
    }

    /**
     * Override the search request. This must send back an entries object.
     *
     * @param RequestContext $context
     * @param SearchRequest $search
     * @return Entries
     */
    public function search(RequestContext $context, SearchRequest $search): Entries
    {
        return new Entries(
            Entry::fromArray('cn=Foo,dc=FreeDSx,dc=local', [
                'cn' => 'Foo',
                'sn' => 'Bar',
                'givenName' => 'Foo',
            ]),
            Entry::fromArray('cn=Chad,dc=FreeDSx,dc=local', [
                'cn' => 'Chad',
                'sn' => 'Sikorra',
                'givenName' => 'Chad',
            ])
        );
    }
}
```

2. Create the server and run it with the request handler above: 

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use Foo\LdapRequestHandler;

$server = new LdapServer(
    (new ServerOptions)->setRequestHandler(new LdapRequestHandler())
);
```

## Handling the RootDSE

If you need more control over the RootDSE that gets returned, you can implement the `RootDseHandlerInterface`. This
allows you to modify / return your own RootDSE in response to a client request for one.

An example of using it to proxy RootDSE requests to a different LDAP server...

1. Create a class implementing `FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface`:

```php
namespace Foo;

use FreeDSx\Ldap\ClientOptions;use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;

class RootDseProxyHandler extends ProxyRequestHandler implements RootDseHandlerInterface
{
    /**
     * Set the options for the LdapClient in the constructor.
     */
    public function __construct()
    {
        parent::__construct(
            (new ClientOptions)
                ->setServers([
                    'dc1.domain.local',
                     'dc2.domain.local',
                 ])
                 ->setBaseDn('dc=domain,dc=local')
        );
    }
    
    public function rootDse(
        RequestContext $context,
        SearchRequest $request,
        Entry $rootDse
    ): Entry {
        return $this->ldap()
            ->search(
                $request,
                ...$context->controls()->toArray()
            )
            ->first();
    }
}
```

2. Use the implemented class when instantiating the LDAP server:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use Foo\RootDseProxyHandler;

$server = new LdapServer(
    (new ServerOptions)->setRootDseHandler(new RootDseProxyHandler())
);

$server->run();
```

The above would pass on a RootDSE request as a proxy and send it back to the client.

## Handling Client Paging Requests

The basic RequestHandlerInterface by default will not support paging requests from clients. To support client paging
search requests you must create a class that implements `FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface`.

An example of using it to handle a client paging request... 

1. Create a class implementing `FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface`:

```php
namespace Foo;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\PagingHandlerInterface;

class MyPagingHandler implements PagingHandlerInterface
{
    /**
     * @inheritDoc
     */
    public function page(
        PagingRequest $pagingRequest,
        RequestContext $context
    ): PagingResponse {
        // Every time a client asks for a new "page" of results, this method will be called.
        
        // Get the unique ID of the paging request.
        // This will remain the same across the series of paging requests.
        $uniqueId = $pagingRequest->getUniqueId();
        // Get the iteration of the "page" set we are on...
        $iteration = $pagingRequest->getIteration();
        // Get the size of the results the client is requesting...
        $size = $pagingRequest->getSize();
        // The actual search request...
        $search = $pagingRequest->getSearchRequest();

        // Perform the logic necessary to build up an Entries object with the results
        // Just an example. Populate this based on actual search, size, and iteration.
        $entries = new Entries(
            Entry::fromArray('cn=Foo,dc=FreeDSx,dc=local', [
                'cn' => 'Foo',
                'sn' => 'Bar',
                'givenName' => 'Foo',
            ]),
            Entry::fromArray('cn=Chad,dc=FreeDSx,dc=local', [
                'cn' => 'Chad',
                'sn' => 'Sikorra',
                'givenName' => 'Chad',
            ])
        );
        
        // Perform actual logic to determine if it is the final result set...
        $isFinalResponse = false;
        
        // ...
 
        if ($isFinalResponse) {
            // If this is the final result in the paging set, make a response indicating as such:
            return PagingResponse::makeFinal($entries);
        } else {
            // If you know an estimate of the remaining entries, pass it as a second param here.
            return PagingResponse::make($entries);
        }
    }
    
    /**
     * @inheritDoc
     */
    public function remove(
        PagingRequest $pagingRequest,
        RequestContext $context
    ): void {
        // This is to indicate that the client is done paging.
        // Use this to clean up any resources involved in handling the paging request.
    }
}
```

2. Use the implemented class when instantiating the LDAP server:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use Foo\MyPagingHandler;

$server = new LdapServer(
    (new ServerOptions)->setPagingHandler(new MyPagingHandler())
);

$server->run();
```

## SASL Authentication

The server supports SASL (Simple Authentication and Security Layer) bind requests. SASL must be explicitly enabled by
configuring the mechanisms you want to support via `ServerOptions::setSaslMechanisms()`. The configured mechanisms are
advertised to clients through the `supportedSaslMechanisms` RootDSE attribute.

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer(
    (new ServerOptions)
        ->setSaslMechanisms(
            ServerOptions::SASL_PLAIN,
            ServerOptions::SASL_CRAM_MD5,
            ServerOptions::SASL_SCRAM_SHA_256,
        )
        ->setRequestHandler(new MyRequestHandler())
);
```

### PLAIN Mechanism

The `PLAIN` mechanism reuses your existing `RequestHandlerInterface::bind()` method. When a client authenticates with
SASL PLAIN, the server extracts the username and password from the SASL credentials and calls `bind()` exactly as it
would for a simple bind.

**Note**: PLAIN transmits credentials in cleartext. Only enable it when the connection is protected by TLS (StartTLS
or `setUseSsl`).

```php
namespace Foo;

use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;

class MyRequestHandler extends GenericRequestHandler
{
    public function bind(string $username, string $password): bool
    {
        // Called for both simple binds and SASL PLAIN binds.
        return $username === 'user' && $password === 'secret';
    }
}
```

### Challenge-Based Mechanisms (CRAM-MD5, DIGEST-MD5, and SCRAM)

`CRAM-MD5`, `DIGEST-MD5`, and the `SCRAM-*` family are challenge-response mechanisms. The server issues a challenge to
the client and verifies the client's response against a digest computed from the user's plaintext password. Because the
verification is cryptographic, the server must be able to look up the plaintext (or equivalent) password for a given
username.

To support these mechanisms, your request handler must additionally implement
`FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface`:

```php
interface SaslHandlerInterface
{
    public function getPassword(
        string $username,
        string $mechanism
    ): ?string;
}
```

Return the user's plaintext password for the given username and mechanism, or `null` if the user does not exist or
should not be permitted to authenticate. Returning `null` results in a generic `invalidCredentials` error — the
mechanism name and `null`/wrong-password cases are not distinguished in the response to avoid user enumeration.

The `$mechanism` parameter lets you apply per-mechanism policy if needed (e.g. disallow weak mechanisms for certain
users), but in most cases you can ignore it and return the same password regardless.

Example handler supporting both simple binds and challenge-based SASL:

```php
namespace Foo;

use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\SaslHandlerInterface;

class MyRequestHandler extends GenericRequestHandler implements SaslHandlerInterface
{
    private array $users = [
        'alice' => 'her-plaintext-password',
        'bob'   => 'his-plaintext-password',
    ];

    // Used for simple binds and SASL PLAIN.
    public function bind(string $username, string $password): bool
    {
        return isset($this->users[$username])
            && $this->users[$username] === $password;
    }

    // Used for CRAM-MD5, DIGEST-MD5, and all SCRAM variants.
    public function getPassword(string $username, string $mechanism): ?string
    {
        return $this->users[$username] ?? null;
    }
}
```

Then enable the desired mechanisms on the server:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;
use Foo\MyRequestHandler;

$server = new LdapServer(
    (new ServerOptions)
        ->setSaslMechanisms(
            ServerOptions::SASL_CRAM_MD5,
            ServerOptions::SASL_DIGEST_MD5,
            ServerOptions::SASL_SCRAM_SHA_256,
        )
        ->setRequestHandler(new MyRequestHandler())
);

$server->run();
```

**SCRAM variants**: The following constants are available for the SCRAM family. `SCRAM-SHA-256` is the recommended
choice for new deployments ([RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) standardises it as the preferred
mechanism, citing SHA-1's known weaknesses).

| Constant                             | Mechanism                       |
|--------------------------------------|---------------------------------|
| `ServerOptions::SASL_SCRAM_SHA_1`    | `SCRAM-SHA-1`                   |
| `ServerOptions::SASL_SCRAM_SHA_256`  | `SCRAM-SHA-256` *(recommended)* |
| `ServerOptions::SASL_SCRAM_SHA_384`  | `SCRAM-SHA-384`                 |
| `ServerOptions::SASL_SCRAM_SHA_512`  | `SCRAM-SHA-512`                 |
| `ServerOptions::SASL_SCRAM_SHA3_512` | `SCRAM-SHA3-512`                |

Channel-binding (`-PLUS`) variants of each are also available (e.g. `SASL_SCRAM_SHA_256_PLUS`) for environments where
TLS channel binding is required.

**Note**: Because `getPassword()` must return the plaintext password, you cannot store passwords as one-way hashes
(e.g. bcrypt) when supporting CRAM-MD5, DIGEST-MD5, or SCRAM. If one-way hashing is a requirement, use `PLAIN` over
TLS instead, which allows password verification via `bind()`.

## StartTLS SSL Certificate Support

To allow clients to issue a StartTLS command against the LDAP server you need to provide an SSL certificate, key, and
key passphrase/password (if needed) when constructing the server class. If these are not present then the StartTLS 
request will not be supported.

Adding the generated certs and keys on construction:

```php
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\LdapServer;

$options = (new ServerOptions)
    # The key can also be bundled in this cert
    ->setSslCert('/path/to/cert.pem')
    # The key for the cert. Not needed if bundled above.
    ->setSslCertKey('/path/to/cert.key')
    # The password/passphrase to read the key (if required)
    ->setSslCertPassphrase('This-Is-My-Secret-Password');

$server = new LdapServer($options);

$server->run();
```
