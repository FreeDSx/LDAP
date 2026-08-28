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
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
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
     * Per-instance memo of operational classification keyed on lowercased attribute name.
     *
     * @var array<string, bool>
     */
    private array $operationalByName = [];

    /**
     * Per-instance memo of the selection decision keyed on attribute description.
     *
     * @var array<string, bool>
     */
    private array $includeByDescription = [];

    /**
     * @param string[] $names
     */
    private function __construct(
        private readonly array $names,
        private readonly bool $wantsUser,
        private readonly bool $wantsOperational,
        private readonly bool $returnNone,
        private readonly bool $typesOnly,
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
        $selected = array_filter(
            $attributes,
            $this->shouldInclude(...),
        );

        // Nothing was withheld, so the entry already is its own projection.
        if (!$this->typesOnly && count($selected) === count($attributes)) {
            return $entry;
        }

        return Entry::raw(
            $entry->getDn(),
            array_values(
                $this->typesOnly
                    ? $this->withoutValues($selected)
                    : $selected,
            ),
        );
    }

    /**
     * Options are part of the description a client asked for, so they survive a types-only request.
     *
     * @param array<Attribute> $attributes
     * @return array<Attribute>
     */
    private function withoutValues(array $attributes): array
    {
        return array_map(
            static fn(Attribute $attribute): Attribute => new Attribute($attribute->getDescription()),
            $attributes,
        );
    }

    private function shouldInclude(Attribute $attribute): bool
    {
        return $this->includeByDescription[$attribute->getDescription()]
            ??= $this->decideInclude($attribute);
    }

    private function decideInclude(Attribute $attribute): bool
    {
        if ($this->names !== [] && in_array(strtolower($attribute->getDescription()), $this->names, true)) {
            return true;
        }

        if ($this->isNamedType($attribute)) {
            return true;
        }

        return $this->isOperational($attribute)
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

    private function isOperational(Attribute $attribute): bool
    {
        $key = strtolower($attribute->getName());

        if (isset($this->operationalByName[$key])) {
            return $this->operationalByName[$key];
        }

        $type = $this->schema->getAttributeType($attribute->getName());

        return $this->operationalByName[$key] = $type !== null
            && $type->usage !== AttributeUsage::UserApplications;
    }
}
