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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;

/**
 * Provides a simple wrapper around paging a search operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Paging
{
    /**
     * @var PagingControl|null
     */
    protected $control;

    /**
     * @var LdapClient
     */
    protected $client;

    /**
     * @var int
     */
    protected $size;

    /**
     * @var SearchRequest
     */
    protected $search;

    /**
     * @var bool
     */
    protected $ended = false;

    /**
     * @param LdapClient $client
     * @param SearchRequest $search
     * @param int $size
     */
    public function __construct(LdapClient $client, SearchRequest $search, int $size = 1000)
    {
        $this->search = $search;
        $this->client = $client;
        $this->size = $size;
    }

    /**
     * Start a new paging operation with a search request. This must be called first if you reuse the paging object.
     *
     * @param SearchRequest $search
     * @param int|null $size
     */
    public function start(SearchRequest $search, ?int $size = null): void
    {
        $this->size = $size ?? $this->size;
        $this->search = $search;
        $this->control = null;
        $this->ended = false;
    }

    /**
     * End the paging operation. This can be triggered at any time.
     *
     * @return $this
     */
    public function end()
    {
        $this->send(0);
        $this->ended = true;

        return $this;
    }

    /**
     * Get the next set of entries of results.
     *
     * @param int|null $size
     * @return Entries
     */
    public function getEntries(?int $size = null): Entries
    {
        return $this->send($size);
    }

    /**
     * @return bool
     */
    public function hasEntries()
    {
        if ($this->ended) {
            return false;
        }

        return $this->control === null || !($this->control->getCookie() === '');
    }

    /**
     * The size may be set to the server's estimate of the total number of entries in the entire result set. Servers
     * that cannot provide such an estimate may set this size to zero.
     *
     * @return int|null
     */
    public function sizeEstimate(): ?int
    {
        return ($this->control !== null) ? $this->control->getSize() : null;
    }

    /**
     * @param int|null $size
     * @return Entries
     * @throws ProtocolException
     */
    protected function send(?int $size = null)
    {
        $cookie = ($this->control !== null) ? $this->control->getCookie() : '';
        $message = $this->client->sendAndReceive($this->search, Controls::paging($size ?? $this->size, $cookie));
        $control = $message->controls()->get(Control::OID_PAGING);
        if ($control !== null && !$control instanceof PagingControl) {
            throw new ProtocolException(sprintf(
                'Expected a paging control, but received: %s.',
                get_class($control)
            ));
        }
        # OpenLDAP returns no paging control in response to an abandon request. However, other LDAP implementations do;
        # such as Active Directory. It's not clear from the paging RFC which is correct.
        if ($control === null && $size !== 0) {
            throw new ProtocolException('Expected a paging control, but received none.');
        }
        $this->control = $control;
        /** @var SearchResponse $response */
        $response = $message->getResponse();

        return $response->getEntries();
    }
}
