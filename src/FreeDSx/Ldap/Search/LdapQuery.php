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

use Fiber;
use Generator;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Search\Result\EntryResult;

/**
 * A fluent builder for constructing and executing LDAP search operations.
 *
 * Obtain an instance via {@see LdapClient::query()}.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class LdapQuery
{
    private ?FilterInterface $filter = null;

    private ?string $baseDn = null;

    private int $scope = SearchRequest::SCOPE_WHOLE_SUBTREE;

    /**
     * @var Attribute[]
     */
    private array $attributes = [];

    private ?int $sizeLimit = null;

    private ?int $timeLimit = null;

    public function __construct(private readonly LdapClient $client)
    {
    }

    /**
     * Set the base DN to search from.
     */
    public function from(string|Dn $baseDn): self
    {
        $this->baseDn = (string) $baseDn;

        return $this;
    }

    /**
     * Search the entire subtree under the base DN (default).
     */
    public function useSubtreeScope(): self
    {
        $this->scope = SearchRequest::SCOPE_WHOLE_SUBTREE;

        return $this;
    }

    /**
     * Search only direct children of the base DN.
     */
    public function useSingleLevelScope(): self
    {
        $this->scope = SearchRequest::SCOPE_SINGLE_LEVEL;

        return $this;
    }

    /**
     * Search only the base DN object itself.
     */
    public function useBaseScope(): self
    {
        $this->scope = SearchRequest::SCOPE_BASE_OBJECT;

        return $this;
    }

    /**
     * Set the attributes to return. Replaces any previously selected attributes.
     */
    public function select(Attribute|string ...$attributes): self
    {
        $this->attributes = array_map(
            fn (Attribute|string $attr) => $attr instanceof Attribute
                ? $attr
                : new Attribute($attr),
            $attributes,
        );

        return $this;
    }

    /**
     * Replace the current filter entirely with the one specified.
     */
    public function where(FilterInterface $filter): self
    {
        $this->filter = $filter;

        return $this;
    }

    /**
     * Add a filter condition using logical AND.
     *
     * - First call: sets the filter directly (no wrapper).
     * - Subsequent calls: appends to an existing {@see AndFilter} or wraps the existing filter in one.
     */
    public function andWhere(FilterInterface $filter): self
    {
        match (true) {
            $this->filter === null => $this->filter = $filter,
            $this->filter instanceof AndFilter => $this->filter->add($filter),
            default => $this->filter = new AndFilter($this->filter, $filter),
        };

        return $this;
    }

    /**
     * Add a filter condition using logical OR.
     *
     * - First call: sets the filter directly (no wrapper).
     * - Subsequent calls: appends to an existing {@see OrFilter} or wraps the existing filter in one.
     */
    public function orWhere(FilterInterface $filter): self
    {
        match (true) {
            $this->filter === null => $this->filter = $filter,
            $this->filter instanceof OrFilter => $this->filter->add($filter),
            default => $this->filter = new OrFilter($this->filter, $filter),
        };

        return $this;
    }

    /**
     * Limit the number of entries the server should return.
     */
    public function sizeLimit(int $sizeLimit): self
    {
        $this->sizeLimit = $sizeLimit;

        return $this;
    }

    /**
     * Limit the time (in seconds) the server should spend on the search.
     */
    public function timeLimit(int $timeLimit): self
    {
        $this->timeLimit = $timeLimit;

        return $this;
    }

    /**
     * Execute the search and return all matching entries.
     *
     * @return Entries<Entry>
     */
    public function get(Control ...$controls): Entries
    {
        return $this->client->search(
            $this->toSearchRequest(),
            ...$controls,
        );
    }

    /**
     * Execute the search and return the first matching entry, or null if none exists.
     *
     * Automatically applies a server-side size limit of 1 unless a limit was already configured.
     */
    public function first(Control ...$controls): ?Entry
    {
        $request = $this->toSearchRequest();

        if ($request->getSizeLimit() === 0) {
            $request->sizeLimit(1);
        }

        return $this->client
            ->search(
                $request,
                ...$controls,
            )->first();
    }

    /**
     * Return a paging helper for iterating through results in pages.
     */
    public function paging(?int $pageSize = null): Paging
    {
        return $this->client->paging(
            $this->toSearchRequest(),
            $pageSize,
        );
    }

    /**
     * Execute the search as a lazy generator, yielding one {@see EntryResult} at a time.
     *
     * Each result exposes both the entry via {@see EntryResult::getEntry()} and the raw
     * protocol message (including any per-entry controls) via {@see EntryResult::getMessage()}.
     *
     * @return Generator<EntryResult>
     */
    public function stream(Control ...$controls): Generator
    {
        /** @var Fiber<mixed, null, void, EntryResult> $fiber */
        $fiber = new Fiber($this->executeSearch(...));

        $result = $fiber->start(...$controls);
        while ($fiber->isSuspended()) {
            if ($result !== null) {
                yield $result;
            }
            $result = $fiber->resume();
        }
    }

    /**
     * Build and return the underlying {@see SearchRequest}.
     *
     * Useful as an escape hatch when you need access to options not exposed by this builder,
     * or when passing the request to other client methods such as {@see LdapClient::vlv()}.
     */
    public function toSearchRequest(): SearchRequest
    {
        $request = new SearchRequest(
            $this->buildFilter(),
            ...$this->attributes,
        );

        if ($this->baseDn !== null) {
            $request->base($this->baseDn);
        }

        $request->setScope($this->scope);

        if ($this->sizeLimit !== null) {
            $request->sizeLimit($this->sizeLimit);
        }

        if ($this->timeLimit !== null) {
            $request->timeLimit($this->timeLimit);
        }

        return $request;
    }

    private function buildFilter(): FilterInterface
    {
        return $this->filter ?? Filters::present('objectClass');
    }

    private function executeSearch(Control ...$controls): void
    {
        $this->client->search(
            $this->toSearchRequest()->useEntryHandler($this->suspendWithResult(...)),
            ...$controls,
        );
    }

    private function suspendWithResult(EntryResult $result): void
    {
        Fiber::suspend($result);
    }
}
