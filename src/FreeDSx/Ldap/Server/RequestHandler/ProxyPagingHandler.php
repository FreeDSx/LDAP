<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestContext;

/**
 * Proxies paging requests to an an existing LDAP client.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ProxyPagingHandler implements PagingHandlerInterface
{
    /**
     * @var LdapClient
     */
    private $client;

    /**
     * @param LdapClient $client
     */
    public function __construct(LdapClient $client)
    {
        $this->client = $client;
    }

    /**
     * @inheritDoc
     */
    public function page(
        PagingRequest $pagingRequest,
        RequestContext $context
    ): PagingResponse {
        $response = $this->client->sendAndReceive(
            $pagingRequest->getSearchRequest(),
            ...$context->controls()->toArray()
        );

        /** @var SearchResponse $searchResponse */
        $searchResponse = $response->getResponse();
        /** @var PagingControl|null $cookie */
        $cookie = $response->controls()->get(Control::OID_PAGING);

        if (!$cookie || $cookie->getCookie() === '') {
            return PagingResponse::makeFinal($searchResponse->getEntries());
        } else {
            return PagingResponse::make(
                $searchResponse->getEntries(),
                $cookie->getSize()
            );
        }
    }

    /**
     * @inheritDoc
     */
    public function remove(
        PagingRequest $pagingRequest,
        RequestContext $context
    ): void {
        // nothing to do for this class...
    }
}
