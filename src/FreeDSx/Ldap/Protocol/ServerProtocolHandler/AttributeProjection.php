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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Schema\Schema;

/**
 * Projects an entry onto a search request's attribute selection list (RFC 4511 §4.5.1.8, RFC 3673).
 *
 *   - empty list / "*" = all user attributes (operational ones only when also named)
 *   - "+"              = all operational attributes (classified via the supplied schema)
 *   - "1.1"            = no attributes (DN only)
 *   - explicit names   = only those, whatever their usage
 *
 * An attribute the schema does not define counts as a user attribute, so unknown ones keep flowing.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class AttributeProjection
{
    /**
     * Selectors that name no attribute type, so a list of only these is decided by usage alone.
     */
    private const SELECTORS = [
        SearchRequest::ATTRIBUTES_ALL_USER,
        SearchRequest::ATTRIBUTES_ALL_OPERATIONAL,
        SearchRequest::ATTRIBUTES_NONE,
    ];

    /**
     * Per-instance memo of the selection decision keyed on attribute description.
     *
     * @var array<string, bool>
     */
    private array $includeByDescription = [];

    /**
     * @param string[] $names
     * @param array<string, true> $rangeSliceTypes Lowercased base types a requested range slice asks for.
     */
    private function __construct(
        private readonly array $names,
        private readonly bool $wantsUser,
        private readonly bool $wantsOperational,
        private readonly bool $returnNone,
        private readonly bool $typesOnly,
        private readonly bool $namesNoType,
        private readonly array $rangeSliceTypes,
        private readonly Schema $schema,
    ) {}

    /**
     * @param Attribute[] $requestedAttrs
     */
    public static function forRequest(
        array $requestedAttrs,
        bool $typesOnly,
        Schema $schema,
    ): self {
        $names = array_map(
            static fn(Attribute $a): string => strtolower($a->getDescription()),
            $requestedAttrs,
        );

        return new self(
            $names,
            count($names) === 0 || in_array(SearchRequest::ATTRIBUTES_ALL_USER, $names, true),
            in_array(SearchRequest::ATTRIBUTES_ALL_OPERATIONAL, $names, true),
            count($names) === 1 && $names[0] === SearchRequest::ATTRIBUTES_NONE,
            $typesOnly,
            array_diff($names, self::SELECTORS) === [],
            self::rangeSliceTypes($requestedAttrs),
            $schema,
        );
    }

    public function project(Entry $entry): Entry
    {
        if ($this->returnNone) {
            return Entry::raw(
                $entry->getDn(),
                [],
            );
        }

        $attributes = $entry->getAttributes();
        $selected = array_values(array_filter(
            $attributes,
            $this->includes(...),
        ));

        return $this->withAttributes(
            $entry,
            $selected,
            count($selected) === count($attributes),
        );
    }

    /**
     * Whether the request selects the attribute.
     */
    public function includes(Attribute $attribute): bool
    {
        return $this->includeByDescription[$attribute->getDescription()]
            ??= $this->decideInclude($attribute);
    }

    /**
     * The entry as returned with just the attributes kept.
     *
     * @param list<Attribute> $kept
     */
    public function withAttributes(
        Entry $entry,
        array $kept,
        bool $keptAll,
    ): Entry {
        if (!$this->typesOnly && $keptAll) {
            return $entry;
        }

        return Entry::raw(
            $entry->getDn(),
            $this->typesOnly
                ? $this->withoutValues($kept)
                : $kept,
        );
    }

    /**
     * @param Attribute[] $requestedAttrs
     * @return array<string, true>
     */
    private static function rangeSliceTypes(array $requestedAttrs): array
    {
        $types = [];

        foreach ($requestedAttrs as $requested) {
            if (self::namesRange($requested)) {
                $types[Attribute::normalizeName($requested->getName())] = true;
            }
        }

        return $types;
    }

    /**
     * Options are part of the description a client asked for, so they survive a types-only request.
     *
     * @param list<Attribute> $attributes
     * @return list<Attribute>
     */
    private function withoutValues(array $attributes): array
    {
        return array_map(
            static fn(Attribute $attribute): Attribute => new Attribute($attribute->getDescription()),
            $attributes,
        );
    }

    private function decideInclude(Attribute $attribute): bool
    {
        if ($this->returnNone) {
            return false;
        }

        if ($this->namesNoType) {
            return $this->wantsByUsage($attribute);
        }

        if (in_array(strtolower($attribute->getDescription()), $this->names, true)) {
            return true;
        }

        if ($this->isNamedType($attribute)) {
            return true;
        }

        if ($this->isNamedSlice($attribute)) {
            return true;
        }

        return $this->wantsByUsage($attribute);
    }

    private function wantsByUsage(Attribute $attribute): bool
    {
        return $this->schema->isOperational($attribute->getDescription())
            ? $this->wantsOperational
            : $this->wantsUser;
    }

    /**
     * Whether a requested name asks for this attribute: its own description, or one it is a subtype of.
     *
     * A type may be named by any of its names or its OID, and naming it asks for the values held under its options
     * and its subtypes too (RFC 4511 4.5.1.8, RFC 4512 2.5.2.1).
     */
    private function isNamedType(Attribute $attribute): bool
    {
        $description = $attribute->getDescription();

        foreach ($this->names as $name) {
            if ($this->schema->isDescriptionSubtypeOf($description, $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether a requested slice of a type is answered by this one.
     */
    private function isNamedSlice(Attribute $attribute): bool
    {
        return isset($this->rangeSliceTypes[Attribute::normalizeName($attribute->getName())]);
    }

    private static function namesRange(Attribute $attribute): bool
    {
        foreach ($attribute->getOptions() as $option) {
            if ($option->isRange()) {
                return true;
            }
        }

        return false;
    }
}
