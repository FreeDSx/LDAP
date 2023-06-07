<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SyncResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;

/**
 * A helper class for an LDAP Content Synchronization Operation, described by RFC 4533.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 * @see https://tools.ietf.org/html/rfc4533
 */
final class SyncRepl
{
    private SearchRequest $searchRequest;

    private LdapClient $client;

    private ?string $cookie = null;

    private ControlBag $controls;

    public function __construct(
        LdapClient $client,
        ?SearchRequest $searchRequest = null
    ) {
        $this->client = $client;
        $this->searchRequest = $searchRequest ?? Operations::search(
            Filters::present('objectClass')
        );
        $this->controls = new ControlBag();
    }

    /**
     * @throws ProtocolException
     */
    public function initialPoll(): SyncResponse
    {
        $message = $this->client->send(
            $this->searchRequest,
            Controls::syncRequest(),
            Controls::manageDsaIt(),
            ...$this->controls->toArray()
        );

        return $this->getResponseAndUpdateCookie($message);
    }

    /**
     * @throws ProtocolException
     */
    public function updatePoll(): SyncResponse
    {
        $message = $this->client->send(
            $this->searchRequest,
            Controls::syncRequest($this->cookie),
            Controls::manageDsaIt(),
            ...$this->controls->toArray()
        );

        return $this->getResponseAndUpdateCookie($message);
    }

    public function controls(): ControlBag
    {
        return $this->controls;
    }

    public function useCookie(?string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }

    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    /**
     * @throws ProtocolException
     */
    private function getResponseAndUpdateCookie(LdapMessageResponse $messageResponse): SyncResponse
    {
        $response = $messageResponse->getResponse();
        if (!$response instanceof SyncResponse) {
            throw new ProtocolException(sprintf(
                'Expected a SyncResponse, got: %s',
                get_class($response)
            ));
        }
        $this->cookie = $response->getCookie();

        return $response;
    }
}
