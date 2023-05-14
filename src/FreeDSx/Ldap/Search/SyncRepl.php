<?php

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
class SyncRepl
{
    /**
     * @var SearchRequest
     */
    protected $searchRequest;

    /**
     * @var LdapClient
     */
    protected $client;

    /**
     * @var string|null
     */
    protected $cookie;

    /**
     * @var ControlBag
     */
    protected $controls;

    /**
     * @param LdapClient $client
     * @param SearchRequest|null $searchRequest
     */
    public function __construct(
        LdapClient $client,
        ?SearchRequest $searchRequest = null
    ) {
        $this->client = $client;
        $this->searchRequest = $searchRequest ?? Operations::search(Filters::present('objectClass'));
        $this->controls = new ControlBag();
    }

    /**
     * @return SyncResponse
     * @throws ProtocolException
     */
    public function initialPoll() : SyncResponse
    {
        $controls = [Controls::syncRequest(), Controls::manageDsaIt()];
        $message = $this->client->send($this->searchRequest, ...$controls, ...$this->controls->toArray());

        return $this->getResponseAndUpdateCookie($message);
    }

    /**
     * @return SyncResponse
     * @throws ProtocolException
     */
    public function updatePoll() : SyncResponse
    {
        $controls = [Controls::syncRequest($this->cookie, SyncRequestControl::MODE_REFRESH_ONLY), Controls::manageDsaIt()];
        $message = $this->client->send($this->searchRequest, ...$controls, ...$this->controls->toArray());

        return $this->getResponseAndUpdateCookie($message);
    }

    /**
     * @return ControlBag
     */
    public function controls() : ControlBag
    {
        return $this->controls;
    }

    /**
     * @param string|null $cookie
     * @return $this
     */
    public function useCookie(?string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }

    /**
     * @return string|null
     */
    public function getCookie()
    {
        return $this->cookie;
    }

    /**
     * @param LdapMessageResponse $messageResponse
     * @return SyncResponse
     * @throws ProtocolException
     */
    private function getResponseAndUpdateCookie(LdapMessageResponse $messageResponse) : SyncResponse
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
