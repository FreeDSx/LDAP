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

namespace FreeDSx\Ldap\Schema\Validation;

/**
 * A rule the schema validator enforces, and who may waive it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum SchemaRule
{
    case AttributeSyntax;

    case ValueLimit;

    case EquivalentValues;

    case DistinctDescriptions;

    case NoUserModification;

    case SettableOperationalAttribute;

    case StructuralClassChange;

    case StructuralClass;

    case RequiredAttributes;

    case AllowedAttributes;

    case DefinedAttributeTypes;

    case SingleValue;

    case NamingAttributes;

    /**
     * Only a structural class change (draft-zeilenga-ldap-relax §3.1) and the operational attributes §3.6 lists.
     */
    public function isRelaxableByControl(): bool
    {
        return match ($this) {
            self::StructuralClassChange,
            self::SettableOperationalAttribute => true,
            default => false,
        };
    }

    /**
     * Value syntax, the value cap and the RFC 4512 §2.2 data model hold whatever the policy.
     */
    public function isRelaxableByPolicy(): bool
    {
        return match ($this) {
            self::AttributeSyntax,
            self::ValueLimit,
            self::EquivalentValues,
            self::DistinctDescriptions => false,
            default => true,
        };
    }
}
