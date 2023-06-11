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

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\DirSync;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Paging;
use FreeDSx\Ldap\Search\RangeRetrieval;
use FreeDSx\Ldap\Search\SyncRepl;
use FreeDSx\Ldap\Search\Vlv;
use FreeDSx\Sasl\Exception\SaslException;
use Stringable;

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

    private ClientOptions $options;

    private ?ClientProtocolHandler $handler = null;

    public function __construct(ClientOptions $options = new ClientOptions())
    {
        $this->options = $options;
    }

    /**
     * A Simple Bind to LDAP with a username and password.
     *
     * @throws Exception\BindException
     */
    public function bind(
        string $username,
        string $password
    ): LdapMessageResponse {
        return $this->sendAndReceive(
            Operations::bind($username, $password)
                ->setVersion($this->options->getVersion())
        );
    }

    /**
     * A SASL Bind to LDAP with SASL options and an optional specific mechanism type.
     *
     * @param array<string, mixed> $options The SASL options (ie. ['username' => '...', 'password' => '...'])
     * @param string $mechanism A specific mechanism to use. If none is supplied, one will be selected.
     * @throws Exception\BindException
     * @throws OperationException
     * @throws SaslException
     */
    public function bindSasl(
        array $options = [],
        string $mechanism = ''
    ): LdapMessageResponse {
        return $this->sendAndReceive(
            Operations::bindSasl($options, $mechanism)
                ->setVersion($this->options->getVersion())
        );
    }

    /**
     * Check whether an entry matches a certain attribute and value.
     *
     * @throws OperationException
     */
    public function compare(
        Dn|string $dn,
        string $attributeName,
        string $value,
        Control ...$controls
    ): bool {
        /** @var CompareResponse $response */
        $response = $this->sendAndReceive(
            Operations::compare(
                $dn,
                $attributeName,
                $value
            ),
            ...$controls
        )->getResponse();

        return $response->getResultCode() === ResultCode::COMPARE_TRUE;
    }

    /**
     * Create a new entry.
     *
     * @throws OperationException
     */
    public function create(
        Entry $entry,
        Control ...$controls
    ): LdapMessageResponse {
        $response = $this->sendAndReceive(
            Operations::add($entry),
            ...$controls
        );
        $entry->changes()->reset();

        return $response;
    }

    /**
     * Read an entry.
     *
     * @param array<Attribute|string> $attributes
     * @throws OperationException
     */
    public function read(
        string $entry = '',
        array $attributes = [],
        Control ...$controls
    ): ?Entry {
        try {
            return $this->readOrFail(
                $entry,
                $attributes,
                ...$controls
            );
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
     * @param array<string|Attribute> $attributes
     * @throws OperationException
     */
    public function readOrFail(
        string $entry = '',
        array $attributes = [],
        Control ...$controls
    ): Entry {
        $entryObj = $this->search(
            Operations::read($entry, ...$attributes),
            ...$controls
        )
            ->first();

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
     * @throws OperationException
     */
    public function delete(
        string $entry,
        Control ...$controls
    ): LdapMessageResponse {
        return $this->sendAndReceive(
            Operations::delete($entry),
            ...$controls
        );
    }

    /**
     * Update an existing entry.
     *
     * @throws OperationException
     */
    public function update(
        Entry $entry,
        Control ...$controls
    ): LdapMessageResponse {
        $response = $this->sendAndReceive(
            Operations::modify(
                $entry->getDn(),
                ...$entry->changes()->toArray()
            ),
            ...$controls
        );
        $entry->changes()->reset();

        return $response;
    }

    /**
     * Move an entry to a new location.
     *
     * @throws OperationException
     */
    public function move(
        Stringable|string $dn,
        Stringable|string $newParentDn
    ): LdapMessageResponse {
        return $this->sendAndReceive(Operations::move(
            (string) $dn,
            (string) $newParentDn
        ));
    }

    /**
     * Rename an entry (changing the RDN).
     *
     * @throws OperationException
     */
    public function rename(
        Stringable|string $dn,
        Stringable|string $newRdn,
        bool $deleteOldRdn = true
    ): LdapMessageResponse {
        return $this->sendAndReceive(Operations::rename(
            $dn,
            $newRdn,
            $deleteOldRdn
        ));
    }

    /**
     * Send a search response and return the entries.
     *
     * @throws OperationException
     */
    public function search(
        SearchRequest $request,
        Control ...$controls
    ): Entries {
        /** @var SearchResponse $response */
        $response = $this->sendAndReceive(
            $request,
            ...$controls
        )->getResponse();

        return $response->getEntries();
    }

    /**
     * A helper for performing a paging based search.
     */
    public function paging(
        SearchRequest $search,
        ?int $size = null
    ): Paging {
        return new Paging(
            client: $this,
            search: $search,
            size: $size ?? $this->options->getPageSize()
        );
    }

    /**
     * A helper for performing a VLV (Virtual List View) based search.
     */
    public function vlv(
        SearchRequest $search,
        SortKey|SortingControl|string $sort,
        int $afterCount
    ): Vlv {
        return new Vlv(
            client: $this,
            search: $search,
            sort: $sort,
            after: $afterCount
        );
    }

    /**
     * A helper for performing a DirSync search operation against AD.
     */
    public function dirSync(
        ?string $rootNc = null,
        FilterInterface $filter = null,
        Attribute|string ...$attributes
    ): DirSync {
        return new DirSync(
            $this,
            $rootNc,
            $filter,
            ...$attributes
        );
    }

    /**
     * A helper for performing a ReplSync / directory synchronization as described in RFC4533.
     */
    public function syncRepl(SyncRequest $syncRequest): SyncRepl
    {
        return new SyncRepl(
            $this,
            $syncRequest,
        );
    }

    /**
     * Send a request operation to LDAP. This may return null if the request expects no response.
     *
     * @throws Exception\BindException
     * @throws Exception\ConnectionException
     * @throws OperationException
     */
    public function send(
        RequestInterface $request,
        Control ...$controls
    ): ?LdapMessageResponse {
        return $this->handler()
            ->send(
                $request,
                ...$controls
            );
    }

    /**
     * Send a request to LDAP that expects a response. If none is received an OperationException is thrown.
     *
     * @throws Exception\BindException
     * @throws Exception\ConnectionException
     * @throws OperationException
     */
    public function sendAndReceive(
        RequestInterface $request,
        Control ...$controls
    ): LdapMessageResponse {
        $response = $this->send(
            $request,
            ...$controls
        );
        if ($response === null) {
            throw new OperationException('Expected an LDAP message response, but none was received.');
        }

        return $response;
    }

    /**
     * Issue a startTLS to encrypt the LDAP connection.
     *
     * @throws Exception\ConnectionException
     * @throws OperationException
     */
    public function startTls(): self
    {
        $this->send(Operations::extended(ExtendedRequest::OID_START_TLS));

        return $this;
    }

    /**
     * Unbind and close the LDAP TCP connection.
     *
     * @throws Exception\ConnectionException
     * @throws OperationException
     */
    public function unbind(): self
    {
        $this->send(Operations::unbind());

        return $this;
    }

    /**
     * Perform a whoami request and get the returned value.
     *
     * @throws OperationException
     */
    public function whoami(): ?string
    {
        /** @var ExtendedResponse $response */
        $response = $this->sendAndReceive(Operations::whoami())->getResponse();

        return $response->getValue();
    }

    /**
     * Get a helper class for handling ranged attributes.
     */
    public function range(): RangeRetrieval
    {
        return new RangeRetrieval($this);
    }

    /**
     * Access to add/set/remove/reset the controls to be used for each request. If you want request specific controls in
     * addition to these, then pass them as a parameter to the send() method.
     */
    public function controls(): ControlBag
    {
        return $this->handler()->controls();
    }

    /**
     * Get the options currently set.
     */
    public function getOptions(): ClientOptions
    {
        return $this->options;
    }

    /**
     * Merge a set of options. Depending on what you are changing, you many want to set the $forceDisconnect param to
     * true, which forces the client to disconnect. After which you would have to manually bind again.
     *
     * @param bool $forceDisconnect Whether the client should disconnect; forcing a manual re-connect / bind. This is
     *                              false by default.
     */
    public function setOptions(
        ClientOptions $options,
        bool $forceDisconnect = false
    ): self {
        $this->options = $options;
        if ($forceDisconnect) {
            $this->unbindIfConnected();
        }

        return $this;
    }

    public function setProtocolHandler(ClientProtocolHandler $handler = null): self
    {
        $this->handler = $handler;

        return $this;
    }

    /**
     * A simple check to determine if this client has an established connection to a server.
     */
    public function isConnected(): bool
    {
        return ($this->handler !== null && $this->handler->isConnected());
    }

    /**
     * Try to clean-up if needed.
     *
     * @throws Exception\ConnectionException
     * @throws OperationException
     */
    public function __destruct()
    {
        $this->unbindIfConnected();
    }

    private function handler(): ClientProtocolHandler
    {
        if ($this->handler === null) {
            $this->handler = new Protocol\ClientProtocolHandler($this->options);
        }

        return $this->handler;
    }

    /**
     * @throws Exception\ConnectionException
     * @throws OperationException
     */
    private function unbindIfConnected(): void
    {
        if ($this->handler !== null && $this->handler->isConnected()) {
            $this->unbind();
        }
    }
}
