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

use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Search\Paging;
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
     * @var array<string, Paging>
     */
    private $pagers = [];

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
        $paging = $this->getPagerForClient($pagingRequest);
        $entries = $paging->getEntries($pagingRequest->getSize());

        if (!$paging->hasEntries()) {
            return PagingResponse::makeFinal($entries);
        } else {
            return PagingResponse::make(
                $entries,
                $paging->sizeEstimate() ?? 0
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
        if (isset($this->pagers[$pagingRequest->getUniqueId()])) {
            unset($this->pagers[$pagingRequest->getUniqueId()]);
        }
    }

    private function getPagerForClient(PagingRequest $pagingRequest): Paging
    {
        if (!isset($this->pagers[$pagingRequest->getUniqueId()])) {
            $this->pagers[$pagingRequest->getUniqueId()] = $this->client->paging(
                $pagingRequest->getSearchRequest(),
                $pagingRequest->getSize()
            );
            $this->pagers[$pagingRequest->getUniqueId()]->isCritical(
                $pagingRequest->isCritical()
            );
        }

        return $this->pagers[$pagingRequest->getUniqueId()];
    }
}
