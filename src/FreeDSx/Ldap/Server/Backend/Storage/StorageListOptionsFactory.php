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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Search\Filter\FilterAttributes;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

use function array_keys;
use function array_map;
use function in_array;
use function min;
use function strtolower;

/**
 * Turns a search request into the storage-level options that answer it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class StorageListOptionsFactory
{
    public function __construct(
        private Schema $schema,
        private SearchLimits $limits = new SearchLimits(),
    ) {}

    /**
     * @param ?SearchLimits $effectiveLimits Per-request limits, or null for the ones this factory was configured with.
     */
    public function make(
        SearchRequest $request,
        Dn $baseDn,
        ControlBag $controls,
        SubentryVisibility $subentries,
        ?SearchLimits $effectiveLimits = null,
    ): StorageListOptions {
        $limits = $effectiveLimits ?? $this->limits;
        $sortingControl = $controls->get(Control::OID_SORTING);

        return new StorageListOptions(
            baseDn: $baseDn,
            subtree: $request->getScope() === SearchRequest::SCOPE_WHOLE_SUBTREE,
            filter: $request->getFilter(),
            timeLimit: $this->effectiveTimeLimit($request->getTimeLimit(), $limits),
            sizeLimit: $request->getSizeLimit(),
            sortKeys: $sortingControl instanceof SortingControl
                ? $sortingControl->getSortKeys()
                : [],
            lookthroughLimit: $limits->maxSearchLookthrough,
            attributes: $this->materializedAttributes($request),
            subentries: $subentries,
        );
    }

    /**
     * The smaller of the requested and server limits, where zero on either side means unbounded.
     */
    private function effectiveTimeLimit(
        int $requestLimit,
        SearchLimits $limits,
    ): int {
        $serverMax = $limits->maxSearchTimeLimit;

        if ($serverMax === 0) {
            return $requestLimit;
        }

        if ($requestLimit === 0) {
            return $serverMax;
        }

        return min(
            $requestLimit,
            $serverMax,
        );
    }

    /**
     * Whether the selection is open ended, either by naming a wildcard or by naming nothing at all.
     *
     * @param array<string> $names
     */
    private function wantsEveryAttribute(array $names): bool
    {
        return $names === []
            || in_array(SearchRequest::ATTRIBUTES_ALL_USER, $names, true)
            || in_array(SearchRequest::ATTRIBUTES_ALL_OPERATIONAL, $names, true);
    }

    /**
     * Base attribute names storage must materialize (requested plus filter-referenced), or null to materialize all.
     *
     * @return list<string>|null
     */
    private function materializedAttributes(SearchRequest $request): ?array
    {
        $names = array_map(
            static fn(Attribute $attribute): string => strtolower($attribute->getName()),
            $request->getAttributes(),
        );

        if ($this->wantsEveryAttribute($names)) {
            return null;
        }

        $filterAttributes = FilterAttributes::referenced($request->getFilter());
        if ($filterAttributes === null) {
            return null;
        }

        $materialized = [];
        foreach ($names as $name) {
            if ($name === SearchRequest::ATTRIBUTES_NONE) {
                continue;
            }

            // Values of a subtype are stored under their own name, so nothing narrower than everything is safe.
            if ($this->schema->hasSubtypes($name)) {
                return null;
            }
            $materialized[$name] = true;

            // A type may be asked for by its OID or any of its names, while it is stored under just one of them.
            foreach ($this->schema->getAttributeType($name)->names ?? [] as $alias) {
                $materialized[strtolower($alias)] = true;
            }
        }
        foreach ($filterAttributes as $attribute) {
            $materialized[$attribute] = true;
        }

        return array_keys($materialized);
    }
}
