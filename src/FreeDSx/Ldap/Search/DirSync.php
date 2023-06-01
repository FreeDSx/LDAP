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

use Closure;
use FreeDSx\Ldap\Control\Ad\DirSyncRequestControl;
use FreeDSx\Ldap\Control\Ad\DirSyncResponseControl;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * Provides a simple wrapper around DirSync for Active Directory.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DirSync
{
    private ?DirSyncResponseControl $lastResponse = null;

    private SearchRequest $search;

    private ?string $namingContext;

    private bool $incrementalValues = true;

    private bool $objectSecurity = false;

    private bool $ancestorFirstOrder = false;

    private ?string $defaultRootNc = null;

    private LdapClient $client;

    private DirSyncRequestControl $dirSyncRequest;

    public function __construct(
        LdapClient $client,
        ?string $namingContext = null,
        ?FilterInterface $filter = null,
        Attribute|string ...$attributes
    ) {
        $this->client = $client;
        $this->namingContext = $namingContext;
        $this->dirSyncRequest = Controls::dirSync();
        $this->search = new SearchRequest(
            $filter ?? Filters::present('objectClass'),
            ...$attributes
        );
    }

    /**
     * A convenience method to easily watch for changes with an anonymous function. The anonymous function will be passed
     * two arguments:
     *
     *     - The Entries object containing the changes.
     *     - A boolean value indicating whether or not the entries are part of the initial sync (the initial sync returns
     *       all entries matching the filter).
     *
     * An optional second argument then determines how many seconds to wait between checking for changes.
     *
     * @param Closure $handler An anonymous function to pass results to.
     * @param int $checkInterval How often to check for changes (in seconds).
     * @throws OperationException
     */
    public function watch(
        Closure $handler,
        int $checkInterval = 10
    ): void {
        $handler($this->getChanges(), true);
        while ($this->hasChanges()) {
            $handler($this->getChanges(), true);
        }

        /** @phpstan-ignore-next-line */
        while (true) {
            sleep($checkInterval);
            $entries = $this->getChanges();
            if ($entries->count() === 0) {
                continue;
            }
            $handler($entries, false);
            /** @phpstan-ignore-next-line */
            while ($this->hasChanges()) {
                $handler($this->getChanges(), false);
            }
        }
    }

    /**
     * Check whether there are more changes to receive.
     */
    public function hasChanges(): bool
    {
        if ($this->lastResponse === null) {
            return false;
        }

        return $this->lastResponse->hasMoreResults();
    }

    /**
     * Get the changes as entries. This may be empty if there are no changes since the last query. This should be
     * followed with a hasChanges() call to determine if more changes are still available.
     *
     * @throws OperationException
     */
    public function getChanges(): Entries
    {
        /** @var LdapMessageResponse $response */
        $response = $this->client->send($this->getSearchRequest(), $this->getDirSyncControl());
        $lastResponse = $response->controls()->get(Control::OID_DIR_SYNC);
        if ($lastResponse === null || !$lastResponse instanceof DirSyncResponseControl) {
            throw new RuntimeException('Expected a DirSync control in the response, but none was received.');
        }
        $this->lastResponse = $lastResponse;
        $this->dirSyncRequest->setCookie($this->lastResponse->getCookie());
        /** @var SearchResponse $searchResponse */
        $searchResponse = $response->getResponse();

        return $searchResponse->getEntries();
    }

    /**
     * The attributes to return from the DirSync search.
     */
    public function selectAttributes(Attribute|string ...$attributes): self
    {
        $this->search->select(...$attributes);

        return $this;
    }

    /**
     * A specific DirSync cookie to use. For example, this could be a cookie from a previous DirSync request, assuming
     * the server still thinks it's valid.
     */
    public function useCookie(string $cookie): self
    {
        $this->dirSyncRequest->setCookie($cookie);

        return $this;
    }

    /**
     * The naming context to run the DirSync against. This MUST be a root naming context.
     */
    public function useNamingContext(?string $namingContext): self
    {
        $this->namingContext = $namingContext;

        return $this;
    }

    /**
     * The LDAP filter to limit the results to.
     */
    public function useFilter(FilterInterface $filter): self
    {
        $this->search->setFilter($filter);

        return $this;
    }

    /**
     * Whether to return only incremental changes on a multivalued attribute that has changed.
     */
    public function useIncrementalValues(bool $incrementalValues = true): self
    {
        $this->incrementalValues = $incrementalValues;

        return $this;
    }

    /**
     * Whether to only retrieve objects and attributes that are accessible to the client.
     */
    public function useObjectSecurity(bool $objectSecurity = true): self
    {
        $this->objectSecurity = $objectSecurity;

        return $this;
    }

    /**
     * Whether the server should return parent objects before child objects.
     */
    public function useAncestorFirstOrder(bool $ancestorFirstOrder = true): self
    {
        $this->ancestorFirstOrder = $ancestorFirstOrder;

        return $this;
    }

    /**
     * Get the cookie currently in use.
     */
    public function getCookie(): string
    {
        return $this->dirSyncRequest->getCookie();
    }

    /**
     * @throws OperationException
     */
    private function getSearchRequest(): SearchRequest
    {
        $this->search->base($this->namingContext ?? $this->getDefaultRootNc());

        return $this->search;
    }

    private function getDirSyncControl(): DirSyncRequestControl
    {
        $flags = 0;
        if ($this->incrementalValues) {
            $flags |= DirSyncRequestControl::FLAG_INCREMENTAL_VALUES;
        }
        if ($this->ancestorFirstOrder) {
            $flags |= DirSyncRequestControl::FLAG_ANCESTORS_FIRST_ORDER;
        }
        if ($this->objectSecurity) {
            $flags |= DirSyncRequestControl::FLAG_OBJECT_SECURITY;
        }
        $this->dirSyncRequest->setFlags($flags);

        return $this->dirSyncRequest;
    }

    /**
     * @throws OperationException
     */
    private function getDefaultRootNc(): string
    {
        if ($this->defaultRootNc === null) {
            $this->defaultRootNc = (string) $this->client->readOrFail(
                    '',
                    ['defaultNamingContext']
                )->get('defaultNamingContext');
        }
        if ($this->defaultRootNc === '') {
            throw new RuntimeException('Unable to determine the root naming context automatically.');
        }

        return $this->defaultRootNc;
    }
}
