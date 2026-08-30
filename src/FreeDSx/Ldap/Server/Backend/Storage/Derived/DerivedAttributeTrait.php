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

namespace FreeDSx\Ldap\Server\Backend\Storage\Derived;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;

use function strcasecmp;

/**
 * Recognizes the operational attributes computed per read, whose values never come from stored rows.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait DerivedAttributeTrait
{
    /**
     * Name to OID for entryDN (RFC 5020), subschemaSubentry (RFC 4512 §4.2) and hasSubordinates (X.501).
     */
    private const DERIVED_ATTRIBUTE_OIDS = [
        AttributeTypeOid::NAME_ENTRY_DN => AttributeTypeOid::OID_ENTRY_DN,
        AttributeTypeOid::NAME_SUBSCHEMA_SUBENTRY => AttributeTypeOid::OID_SUBSCHEMA_SUBENTRY,
        AttributeTypeOid::NAME_HAS_SUBORDINATES => AttributeTypeOid::OID_HAS_SUBORDINATES,
    ];

    /**
     * Whether a description names the given type, by either its name or its OID, ignoring options and case.
     */
    private static function describesType(
        string $attributeDescription,
        string $name,
    ): bool {
        $type = Attribute::normalizeName($attributeDescription);

        return strcasecmp($type, $name) === 0
            || $type === (self::DERIVED_ATTRIBUTE_OIDS[$name] ?? null);
    }

    /**
     * The canonical name a description refers to however it is spelled, or null when it names no derived attribute.
     */
    private static function derivedTypeName(string $attributeDescription): ?string
    {
        foreach (array_keys(self::DERIVED_ATTRIBUTE_OIDS) as $name) {
            if (self::describesType($attributeDescription, $name)) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Whether a description names any derived attribute, for callers that treat them alike.
     */
    private static function describesAnyDerivedAttribute(string $attributeDescription): bool
    {
        return self::derivedTypeName($attributeDescription) !== null;
    }

    /**
     * Whether a description asks for the given derived type, either by naming it or through the operational wildcard.
     */
    private static function selectsDerivedType(
        string $attributeDescription,
        string $name,
    ): bool {
        return self::describesType($attributeDescription, $name)
            || self::describesType($attributeDescription, SearchRequest::ATTRIBUTES_ALL_OPERATIONAL);
    }

    /**
     * Whether a requested attribute list asks for the given derived type.
     *
     * @param array<Attribute> $requested
     */
    private static function requestsDerivedType(
        array $requested,
        string $name,
    ): bool {
        foreach ($requested as $attribute) {
            if (self::selectsDerivedType($attribute->getName(), $name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The derived types a requested attribute list asks for, in a stable order.
     *
     * @param array<Attribute> $requested
     * @return list<string>
     */
    private static function derivedTypesRequested(array $requested): array
    {
        $names = [];

        foreach (array_keys(self::DERIVED_ATTRIBUTE_OIDS) as $name) {
            if (self::requestsDerivedType($requested, $name)) {
                $names[] = $name;
            }
        }

        return $names;
    }
}
