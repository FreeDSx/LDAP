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

namespace FreeDSx\Ldap\Server\Backend\Storage\Search;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Search\Filter\FilterAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedAttributeTrait;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkWindow;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageSlice;
use FreeDSx\Ldap\Server\Backend\Storage\Search\Options\ListScope;
use FreeDSx\Ldap\Server\Backend\Storage\Search\Options\ReadBounds;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

use function array_intersect;
use function array_keys;
use function array_map;
use function array_values;
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
    use DerivedAttributeTrait;

    public function __construct(
        private Schema $schema,
        private SearchLimits $limits = new SearchLimits(),
        private LinkedAttributes $linked = new LinkedAttributes(new Schema()),
    ) {}

    /**
     * @param ?SearchLimits $effectiveLimits Per-request limits, or null for the ones this factory was configured with.
     * @param ?PageSlice $slice Reads one bounded piece of the result rather than the whole of it.
     */
    public function make(
        SearchRequest $request,
        Dn $baseDn,
        ControlBag $controls,
        SubentryVisibility $subentries,
        ?SearchLimits $effectiveLimits = null,
        ?PageSlice $slice = null,
    ): StorageListOptions {
        $limits = $effectiveLimits ?? $this->limits;
        $sortingControl = $controls->get(Control::OID_SORTING);
        $timeLimit = $this->effectiveTimeLimit(
            $request->getTimeLimit(),
            $limits,
        );

        return new StorageListOptions(
            scope: new ListScope(
                baseDn: $baseDn,
                subtree: $request->getScope() === SearchRequest::SCOPE_WHOLE_SUBTREE,
                subentries: $subentries,
            ),
            filter: $request->getFilter(),
            projection: $this->projectionFor(
                $request,
                $limits,
            ),
            sortKeys: $sortingControl instanceof SortingControl
                ? $sortingControl->getSortKeys()
                : [],
            bounds: new ReadBounds(
                deadline: $slice->deadline ?? ($timeLimit > 0
                    ? microtime(true) + $timeLimit
                    : null),
                lookthroughLimit: $limits->maxSearchLookthrough(),
                slice: $slice,
            ),
        );
    }

    /**
     * What each entry the request reads materializes, which a base object read needs without the rest of the options.
     *
     * @param ?SearchLimits $effectiveLimits Per-request limits, or null for the ones this factory was configured with.
     */
    public function projectionFor(
        SearchRequest $request,
        ?SearchLimits $effectiveLimits = null,
    ): EntryProjection {
        $linkCap = ($effectiveLimits ?? $this->limits)->maxLinkedValues();

        return new EntryProjection(
            attributes: $this->materializedAttributes($request),
            linkCap: match ($linkCap) {
                null => EntryProjection::DEFAULT_LINK_CAP,
                0 => null,
                default => $linkCap,
            },
            withHasSubordinates: $this->wantsHasSubordinates($request),
            windows: $this->linkWindows($request),
            backlinks: $this->backlinksWanted($request),
        );
    }

    /**
     * @return list<string>
     */
    private function backlinksWanted(SearchRequest $request): array
    {
        $backlinks = $this->linked->backlinks();

        if ($backlinks->isEmpty()) {
            return [];
        }
        $names = array_map(
            static fn(Attribute $attribute): string => Attribute::normalizeName($attribute->getName()),
            $request->getAttributes(),
        );

        if (in_array(SearchRequest::ATTRIBUTES_ALL_OPERATIONAL, $names, true)) {
            return $backlinks->names();
        }

        return array_values(array_intersect(
            $backlinks->names(),
            $names,
        ));
    }

    /**
     * The slices the request asks for.
     *
     * @return array<string, LinkWindow>
     *
     * @throws OperationException when a range names a slice that cannot be served
     */
    private function linkWindows(SearchRequest $request): array
    {
        $windows = [];

        foreach ($request->getAttributes() as $attribute) {
            foreach ($attribute->getOptions() as $option) {
                $window = LinkWindow::fromOption($option);

                if ($window === null) {
                    continue;
                }
                $name = Attribute::normalizeName($attribute->getName());

                // Only values held apart from the entry can be handed over a slice at a time.
                if (!$this->linked->heldApart(new Attribute($name))) {
                    throw new OperationException(
                        sprintf('The attribute "%s" is not one this server ranges.', $name),
                        ResultCode::UNWILLING_TO_PERFORM,
                    );
                }

                $windows[$name] = $window;
            }
        }

        return $windows;
    }

    /**
     * A backend that can answer this alongside the row saves the per-entry lookup the resolver would otherwise make.
     */
    private function wantsHasSubordinates(SearchRequest $request): bool
    {
        return self::requestsDerivedType(
            $request->getAttributes(),
            AttributeTypeOid::NAME_HAS_SUBORDINATES,
        );
    }

    /**
     * The smaller of the requested and server limits, where zero on either side means unbounded.
     */
    private function effectiveTimeLimit(
        int $requestLimit,
        SearchLimits $limits,
    ): int {
        $serverMax = $limits->maxSearchTimeLimit();

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
