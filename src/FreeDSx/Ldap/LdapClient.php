<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\DirSync;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Paging;
use FreeDSx\Ldap\Search\RangeRetrieval;
use FreeDSx\Ldap\Search\Vlv;

/**
 * The LDAP client.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdapClient
{
    public const REFERRAL_IGNORE = 'ignore';

    public const REFERRAL_FOLLOW = 'follow';

    public const REFERRAL_THROW = 'throw';

    /**
     * @var array
     */
    protected $options = [
        'version' => 3,
        'servers' => [],
        'port' => 389,
        'base_dn' => null,
        'page_size' => 1000,
        'use_ssl' => false,
        'ssl_validate_cert' => true,
        'ssl_allow_self_signed' => null,
        'ssl_ca_cert' => null,
        'ssl_peer_name' => null,
        'timeout_connect' => 3,
        'timeout_read' => 10,
        'referral' => 'throw',
        'referral_chaser' => null,
        'referral_limit' => 10,
    ];

    /**
     * @var ClientProtocolHandler|null
     */
    protected $handler;

    /**
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        $this->options = array_merge($this->options, $options);
    }

    /**
     * A Simple Bind to LDAP with a username and password.
     *
     * @param string $username
     * @param string $password
     * @return LdapMessageResponse
     * @throws BindException
     * @throws OperationException
     */
    public function bind(string $username, string $password): LdapMessageResponse
    {
        return $this->sendAndReceive(Operations::bind($username, $password)->setVersion($this->options['version']));
    }

    /**
     * A SASL Bind to LDAP with SASL options and an optional specific mechanism type.
     *
     * @param array $options The SASL options (ie. ['username' => '...', 'password' => '...'])
     * @param string $mechanism A specific mechanism to use. If none is supplied, one will be selected.
     * @return LdapMessageResponse
     * @throws BindException
     * @throws OperationException
     */
    public function bindSasl(array $options = [], string $mechanism = ''): LdapMessageResponse
    {
        return $this->sendAndReceive(Operations::bindSasl($options, $mechanism)->setVersion($this->options['version']));
    }

    /**
     * Check whether or not an entry matches a certain attribute and value.
     *
     * @param string|\FreeDSx\Ldap\Entry\Dn $dn
     * @param string $attributeName
     * @param string $value
     * @param Control ...$controls
     * @return bool
     * @throws OperationException
     */
    public function compare($dn, string $attributeName, string $value, Control ...$controls): bool
    {
        /** @var \FreeDSx\Ldap\Operation\Response\CompareResponse $response */
        $response = $this->sendAndReceive(Operations::compare($dn, $attributeName, $value), ...$controls)->getResponse();

        return $response->getResultCode() === ResultCode::COMPARE_TRUE;
    }

    /**
     * Create a new entry.
     *
     * @param Entry $entry
     * @param Control ...$controls
     * @return LdapMessageResponse
     * @throws OperationException
     */
    public function create(Entry $entry, Control ...$controls): LdapMessageResponse
    {
        $response = $this->sendAndReceive(Operations::add($entry), ...$controls);
        $entry->changes()->reset();

        return $response;
    }

    /**
     * Read an entry.
     *
     * @param string $entry
     * @param string[] $attributes
     * @param Control ...$controls
     * @return Entry|null
     * @throws Exception\OperationException
     */
    public function read(string $entry = '', $attributes = [], Control ...$controls): ?Entry
    {
        try {
            return $this->readOrFail($entry, $attributes, ...$controls);
        } catch (Exception\OperationException $e) {
            if ($e->getCode() === ResultCode::NO_SUCH_OBJECT) {
                return null;
            }
            throw $e;
        }
    }

    /**
     * Read an entry from LDAP. If the entry is not found an OperationException is thrown.
     *
     * @param string $entry
     * @param string[] $attributes
     * @param Control ...$controls
     * @return Entry
     * @throws OperationException
     */
    public function readOrFail(string $entry = '', $attributes = [], Control ...$controls): Entry
    {
        $entryObj = $this->search(Operations::read($entry, ...$attributes), ...$controls)->first();
        if ($entryObj === null) {
            throw new OperationException(sprintf(
                'The entry "%s" was not found.',
                $entry
            ), ResultCode::NO_SUCH_OBJECT);
        }

        return $entryObj;
    }

    /**
     * Delete an entry.
     *
     * @param string $entry
     * @param Control ...$controls
     * @return LdapMessageResponse
     * @throws OperationException
     */
    public function delete(string $entry, Control ...$controls): LdapMessageResponse
    {
        return $this->sendAndReceive(Operations::delete($entry), ...$controls);
    }

    /**
     * Update an existing entry.
     *
     * @param Entry $entry
     * @param Control ...$controls
     * @return LdapMessageResponse
     * @throws OperationException
     */
    public function update(Entry $entry, Control ...$controls): LdapMessageResponse
    {
        $response = $this->sendAndReceive(Operations::modify($entry->getDn(), ...$entry->changes()), ...$controls);
        $entry->changes()->reset();

        return $response;
    }

    /**
     * Move an entry to a new location.
     *
     * @param string|Entry $dn
     * @param string|Entry $newParentDn
     * @return LdapMessageResponse
     * @throws OperationException
     */
    public function move($dn, $newParentDn): LdapMessageResponse
    {
        return $this->sendAndReceive(Operations::move($dn, $newParentDn));
    }

    /**
     * Rename an entry (changing the RDN).
     *
     * @param string|Entry $dn
     * @param string $newRdn
     * @param bool $deleteOldRdn
     * @return LdapMessageResponse
     * @throws OperationException
     */
    public function rename($dn, $newRdn, bool $deleteOldRdn = true): LdapMessageResponse
    {
        return $this->sendAndReceive(Operations::rename($dn, $newRdn, $deleteOldRdn));
    }

    /**
     * Send a search response and return the entries.
     *
     * @param SearchRequest $request
     * @param Control ...$controls
     * @return \FreeDSx\Ldap\Entry\Entries
     * @throws OperationException
     */
    public function search(SearchRequest $request, Control ...$controls): Entries
    {
        /** @var \FreeDSx\Ldap\Operation\Response\SearchResponse $response */
        $response = $this->sendAndReceive($request, ...$controls)->getResponse();

        return $response->getEntries();
    }

    /**
     * A helper for performing a paging based search.
     *
     * @param SearchRequest $search
     * @param int $size
     * @return Paging
     */
    public function paging(SearchRequest $search, ?int $size = null): Paging
    {
        return new Paging($this, $search, $size ?? $this->options['page_size']);
    }

    /**
     * A helper for performing a VLV (Virtual List View) based search.
     *
     * @param SearchRequest $search
     * @param SortingControl|string|SortKey $sort
     * @param int $afterCount
     * @return Vlv
     */
    public function vlv(SearchRequest $search, $sort, int $afterCount): Vlv
    {
        return new Vlv($this, $search, $sort, $afterCount);
    }

    /**
     * A helper for performing a DirSync search operation against AD.
     *
     * @param string|null $rootNc
     * @param FilterInterface|null $filter
     * @param mixed ...$attributes
     * @return DirSync
     */
    public function dirSync(?string $rootNc = null, FilterInterface $filter = null, ...$attributes): DirSync
    {
        return new DirSync($this, $rootNc, $filter, ...$attributes);
    }

    /**
     * Send a request operation to LDAP. This may return null if the request expects no response.
     *
     * @param RequestInterface $request
     * @param Control ...$controls
     * @return LdapMessageResponse|null
     * @throws Exception\ConnectionException
     * @throws Exception\UnsolicitedNotificationException
     * @throws OperationException
     */
    public function send(RequestInterface $request, Control ...$controls): ?LdapMessageResponse
    {
        return $this->handler()->send($request, ...$controls);
    }

    /**
     * Send a request to LDAP that expects a response. If none is received an OperationException is thrown.
     *
     * @param RequestInterface $request
     * @param Control ...$controls
     * @return LdapMessageResponse
     * @throws OperationException
     */
    public function sendAndReceive(RequestInterface $request, Control ...$controls): LdapMessageResponse
    {
        $response = $this->send($request, ...$controls);
        if ($response === null) {
            throw new OperationException('Expected an LDAP message response, but none was received.');
        }

        return $response;
    }

    /**
     * Issue a startTLS to encrypt the LDAP connection.
     *
     * @return $this
     * @throws OperationException
     */
    public function startTls()
    {
        $this->send(Operations::extended(ExtendedRequest::OID_START_TLS));

        return $this;
    }

    /**
     * Unbind and close the LDAP TCP connection.
     *
     * @return $this
     * @throws OperationException
     */
    public function unbind()
    {
        $this->send(Operations::unbind());

        return $this;
    }

    /**
     * Perform a whoami request and get the returned value.
     *
     * @return string
     * @throws OperationException
     */
    public function whoami(): ?string
    {
        /** @var \FreeDSx\Ldap\Operation\Response\ExtendedResponse $response */
        $response = $this->sendAndReceive(Operations::whoami())->getResponse();

        return $response->getValue();
    }

    /**
     * Get a helper class for handling ranged attributes.
     *
     * @return RangeRetrieval
     */
    public function range(): RangeRetrieval
    {
        return new RangeRetrieval($this);
    }
    
    /**
     * Access to add/set/remove/reset the controls to be used for each request. If you want request specific controls in
     * addition to these, then pass them as a parameter to the send() method.
     *
     * @return ControlBag
     */
    public function controls(): ControlBag
    {
        return $this->handler()->controls();
    }

    /**
     * Get the options currently set.
     *
     * @return array
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Merge a set of options.
     *
     * @param array $options
     * @return $this
     */
    public function setOptions(array $options)
    {
        $this->options = array_merge($this->options, $options);

        return $this;
    }

    /**
     * @param ClientProtocolHandler|null $handler
     * @return $this
     */
    public function setProtocolHandler(ClientProtocolHandler $handler = null)
    {
        $this->handler = $handler;

        return $this;
    }

    /**
     * A simple check to determine if this client has an established connection to a server.
     *
     * @return bool
     */
    public function isConnected(): bool
    {
        return ($this->handler !== null && $this->handler->isConnected());
    }

    /**
     * Try to clean-up if needed.
     */
    public function __destruct()
    {
        if ($this->handler !== null && $this->handler->isConnected()) {
            $this->unbind();
        }
    }

    protected function handler(): ClientProtocolHandler
    {
        if ($this->handler === null) {
            $this->handler = new Protocol\ClientProtocolHandler($this->options);
        }

        return $this->handler;
    }
}
