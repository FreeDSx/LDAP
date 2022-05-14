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
use FreeDSx\Ldap\LdapServer;

$server = LdapServer::makeProxy(
    // The LDAP server to proxy connections to...
    'ldap.example.com',
    // Any additional LdapClient options for the proxy...
    [],
    // Any additional LdapServer options. In this case, run over port 3389
    [
        'port' => 3389,
    ]
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
        $this->options = [
            'servers' => ['dc1.domain.local', 'dc2.domain.local'],
            'base_dn' => 'dc=domain,dc=local',
        ];
    }
}
```

2. Create the server and run it with the request handler above: 

```php
use FreeDSx\Ldap\LdapServer;
use Foo\LdapProxyHandler;

$server = new LdapServer([ 'request_handler' => LdapProxyHandler::class ]);
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
use FreeDSx\Ldap\LdapServer;
use Foo\LdapRequestHandler;

$server = new LdapServer([ 'request_handler' => LdapRequestHandler::class ]);
$server->run();
```

## Handling the RootDSE

If you need more control over the RootDSE that gets returned, you can implement the `RootDseHandlerInterface`. This
allows you to modify / return your own RootDSE in response to a client request for one.

An example of using it to proxy RootDSE requests to a different LDAP server...

1. Create a class implementing `FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface`:

```php
namespace Foo;

use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestHandler\ProxyRequestHandler;
use FreeDSx\Ldap\Server\RequestHandler\RootDseHandlerInterface;

class RootDseProxyHandler extends ProxyRequestHandler implements RootDseHandlerInterface
{
    /**
     * Set the options for the LdapClient in the constructor.
     */
    public function __construct()
    {
        $this->options = [
            'servers' => ['dc1.domain.local', 'dc2.domain.local'],
            'base_dn' => 'dc=domain,dc=local',
        ];
    }
    
    public function rootDse(RequestContext $context, SearchRequest $request, Entry $rootDse): Entry
    {
        return $this->ldap()
            ->search($request, ...$context->controls()->toArray())
            ->first();
    }
}
```

2. Use the implemented class when instantiating the LDAP server:

```php
use FreeDSx\Ldap\LdapServer;
use Foo\RootDseProxyHandler;

$server = new LdapServer(['rootdse_handler' => RootDseProxyHandler::class]);
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
use FreeDSx\Ldap\LdapServer;
use Foo\MyPagingHandler;

$server = new LdapServer();
$server->usePagingHandler(new MyPagingHandler());
$server->run();
```

## StartTLS SSL Certificate Support

To allow clients to issue a StartTLS command against the LDAP server you need to provide an SSL certificate, key, and
key passphrase/password (if needed) when constructing the server class. If these are not present then the StartTLS 
request will not be supported.

Adding the generated certs and keys on construction:

```php
use FreeDSx\Ldap\LdapServer;

$server = new LdapServer([
    # The key can also be bundled in this cert
    'ssl_cert' => '/path/to/cert.pem',
    # The key for the cert. Not needed if bundled above.
    'ssl_cert_key' => '/path/to/cert.key',
    # The password/passphrase to read the key (if required)
    'ssl_cert_passphrase' => 'This-Is-My-Secret-Password',
]);

$server->run();
```
