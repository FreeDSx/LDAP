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

namespace FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Definition\LdapSyntax;
use FreeDSx\Ldap\Schema\Definition\MatchingRule;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Definition\ObjectClass;
use FreeDSx\Ldap\Schema\Definition\SyntaxOid;
use FreeDSx\Ldap\Schema\Matching\Comparator\ObjectIdentifierComparator;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;

/**
 * Registry of schema definitions; built incrementally via add*() methods.
 *
 * @api
 */
final class Schema
{
    /**
     * Equality rules that ignore case, so a case-folded comparison is equivalent to them.
     */
    private const CASE_INSENSITIVE_EQUALITY_OIDS = [
        MatchingRuleOid::OID_CASE_IGNORE_MATCH,
        MatchingRuleOid::OID_CASE_IGNORE_IA5_MATCH,
    ];

    /**
     * @var array<string, AttributeType>
     */
    private array $attributeTypes = [];

    /**
     * Every OID named as a SUP, built on first use and dropped whenever the type set changes.
     *
     * @var array<string, true>|null
     */
    private ?array $superTypeOids = null;

    /**
     * Bound to this schema, so it is built once rather than per lookup.
     */
    private ?ObjectIdentifierComparator $objectIdentifierComparator = null;

    /**
     * @var array<string, ObjectClass>
     */
    private array $objectClasses = [];

    /**
     * @var array<string, MatchingRule>
     */
    private array $matchingRules = [];

    /**
     * @var array<string, LdapSyntax>
     */
    private array $ldapSyntaxes = [];

    public function addAttributeType(AttributeType $type): static
    {
        $this->attributeTypes[$type->oid] = $type;
        foreach ($type->names as $name) {
            $this->attributeTypes[strtolower($name)] = $type;
        }
        $this->superTypeOids = null;

        return $this;
    }

    public function addObjectClass(ObjectClass $class): static
    {
        $this->objectClasses[$class->oid] = $class;
        foreach ($class->names as $name) {
            $this->objectClasses[strtolower($name)] = $class;
        }

        return $this;
    }

    public function addMatchingRule(MatchingRule $rule): static
    {
        $this->matchingRules[$rule->oid] = $rule;
        foreach ($rule->names as $name) {
            $this->matchingRules[strtolower($name)] = $rule;
        }

        return $this;
    }

    public function addSyntax(LdapSyntax $syntax): static
    {
        $this->ldapSyntaxes[$syntax->oid] = $syntax;

        return $this;
    }

    public function getAttributeType(string $nameOrOid): ?AttributeType
    {
        return $this->attributeTypes[$nameOrOid]
            ?? $this->attributeTypes[strtolower($nameOrOid)]
            ?? null;
    }

    /**
     * Whether the attribute orders numerically.
     */
    public function isIntegerOrdered(string $nameOrOid): ?bool
    {
        $attributeType = $this->getAttributeType($nameOrOid);

        if ($attributeType === null) {
            return null;
        }

        if ($attributeType->orderingOid !== null) {
            return $attributeType->orderingOid === MatchingRuleOid::OID_INTEGER_ORDERING_MATCH;
        }

        return $attributeType->syntaxOid === SyntaxOid::OID_INTEGER;
    }

    /**
     * The effective SUBSTR rule OID, walking the SUP chain when the type declares none directly.
     */
    public function getSubstringRuleOid(string $nameOrOid): ?string
    {
        $attributeType = $this->getAttributeType($nameOrOid);
        $seen = [];

        while ($attributeType !== null && !isset($seen[$attributeType->oid])) {
            if ($attributeType->substringOid !== null) {
                return $attributeType->substringOid;
            }

            $seen[$attributeType->oid] = true;
            $attributeType = $attributeType->superTypeOid !== null
                ? $this->getAttributeType($attributeType->superTypeOid)
                : null;
        }

        return null;
    }

    /**
     * Whether one attribute type is the other, or descends from it through the SUP chain.
     *
     * Either side may be given as an OID or any of the names the type is known by.
     */
    public function isTypeOrSubtypeOf(
        string $nameOrOid,
        string $ofNameOrOid,
    ): bool {
        $type = $this->getAttributeType($nameOrOid);
        $of = $this->getAttributeType($ofNameOrOid);

        if ($type === null || $of === null) {
            return false;
        }

        $seen = [];
        while ($type !== null) {
            if ($type->oid === $of->oid) {
                return true;
            }
            if ($type->superTypeOid === null || isset($seen[$type->superTypeOid])) {
                return false;
            }
            $seen[$type->superTypeOid] = true;
            $type = $this->getAttributeType($type->superTypeOid);
        }

        return false;
    }

    /**
     * Whether any other attribute type names this one as its SUP, so an assertion on it must also cover theirs.
     */
    public function hasSubtypes(string $nameOrOid): bool
    {
        $attributeType = $this->getAttributeType($nameOrOid);

        if ($attributeType === null) {
            return false;
        }

        if ($this->superTypeOids === null) {
            $oids = [];
            foreach ($this->attributeTypes as $type) {
                if ($type->superTypeOid !== null) {
                    $oids[$type->superTypeOid] = true;
                }
            }
            $this->superTypeOids = $oids;
        }

        return isset($this->superTypeOids[$attributeType->oid]);
    }

    /**
     * Whether the attribute matches without regard to case, or null when it is not defined here.
     */
    public function isCaseInsensitiveMatched(string $nameOrOid): ?bool
    {
        $attributeType = $this->getAttributeType($nameOrOid);

        if ($attributeType?->equalityOid === null) {
            return null;
        }

        return in_array(
            $attributeType->equalityOid,
            self::CASE_INSENSITIVE_EQUALITY_OIDS,
            true,
        );
    }

    /**
     * The OID a descriptor aliases (RFC 4512 §1.4), or null when nothing here defines it.
     */
    public function oidFor(string $nameOrOid): ?string
    {
        return $this->getObjectClass($nameOrOid)->oid
            ?? $this->getAttributeType($nameOrOid)->oid
            ?? $this->getMatchingRule($nameOrOid)?->oid;
    }

    /**
     * Every spelling of one object identifier, so a store comparing text can still be asked about it.
     *
     * @return list<string>|null null when nothing here defines the value
     */
    public function oidSpellings(string $nameOrOid): ?array
    {
        $names = $this->getObjectClass($nameOrOid)->names
            ?? $this->getAttributeType($nameOrOid)->names
            ?? $this->getMatchingRule($nameOrOid)?->names;
        $oid = $this->oidFor($nameOrOid);

        if ($oid === null) {
            return null;
        }

        return array_values(array_unique([
            $oid,
            ...($names ?? []),
        ]));
    }

    public function getObjectClass(string $nameOrOid): ?ObjectClass
    {
        return $this->objectClasses[$nameOrOid]
            ?? $this->objectClasses[strtolower($nameOrOid)]
            ?? null;
    }

    public function getMatchingRule(string $nameOrOid): ?MatchingRule
    {
        return $this->matchingRules[$nameOrOid]
            ?? $this->matchingRules[strtolower($nameOrOid)]
            ?? null;
    }

    public function getSyntax(string $oid): ?LdapSyntax
    {
        return $this->ldapSyntaxes[$oid] ?? null;
    }

    public function getComparator(string $ruleNameOrOid): ?MatchingRuleComparatorInterface
    {
        $rule = $this->getMatchingRule($ruleNameOrOid);

        if ($rule === null) {
            return null;
        }

        // Resolving a descriptor needs the schema, which does not exist yet when the rule is parsed.
        if ($rule->oid === MatchingRuleOid::OID_OBJECT_IDENTIFIER_MATCH) {
            return $this->objectIdentifierComparator ??= new ObjectIdentifierComparator($this);
        }

        return $rule->comparator;
    }

    /**
     * @return list<AttributeType>
     */
    public function getAttributeTypes(): array
    {
        return $this->uniqueObjects($this->attributeTypes);
    }

    /**
     * @return list<ObjectClass>
     */
    public function getObjectClasses(): array
    {
        return $this->uniqueObjects($this->objectClasses);
    }

    /**
     * @return list<MatchingRule>
     */
    public function getMatchingRules(): array
    {
        return $this->uniqueObjects($this->matchingRules);
    }

    /**
     * @return list<LdapSyntax>
     */
    public function getLdapSyntaxes(): array
    {
        return array_values($this->ldapSyntaxes);
    }

    /**
     * Merges another schema into a new instance; definitions from $other override on OID/name collision.
     *
     * Vendor extensions the incoming definition omits are carried forward, so merging schema parsed from another
     * directory cannot silently drop protections such as X-CONFIDENTIAL. Override an extension by giving it a
     * different value rather than by omitting it.
     */
    public function merge(Schema $other): static
    {
        $merged = clone $this;
        foreach ($other->getAttributeTypes() as $type) {
            $merged->addAttributeType($this->carriedAttributeType($type));
        }
        foreach ($other->getObjectClasses() as $class) {
            $merged->addObjectClass($this->carriedObjectClass($class));
        }
        foreach ($other->getMatchingRules() as $rule) {
            $merged->addMatchingRule($this->carriedMatchingRule($rule));
        }
        foreach ($other->getLdapSyntaxes() as $syntax) {
            $merged->addSyntax($this->carriedSyntax($syntax));
        }

        return $merged;
    }

    private function carriedAttributeType(AttributeType $incoming): AttributeType
    {
        $existing = $this->getAttributeType($incoming->oid);

        if ($existing === null || $existing->extensions === []) {
            return $incoming;
        }

        return $incoming->withExtensions($incoming->extensions + $existing->extensions);
    }

    private function carriedObjectClass(ObjectClass $incoming): ObjectClass
    {
        $existing = $this->getObjectClass($incoming->oid);

        if ($existing === null || $existing->extensions === []) {
            return $incoming;
        }

        return $incoming->withExtensions($incoming->extensions + $existing->extensions);
    }

    private function carriedMatchingRule(MatchingRule $incoming): MatchingRule
    {
        $existing = $this->getMatchingRule($incoming->oid);

        if ($existing === null || $existing->extensions === []) {
            return $incoming;
        }

        return $incoming->withExtensions($incoming->extensions + $existing->extensions);
    }

    private function carriedSyntax(LdapSyntax $incoming): LdapSyntax
    {
        $existing = $this->getSyntax($incoming->oid);

        if ($existing === null || $existing->extensions === []) {
            return $incoming;
        }

        return $incoming->withExtensions($incoming->extensions + $existing->extensions);
    }

    /**
     * Deduplicates an array of objects by identity, preserving insertion order.
     *
     * @template T of object
     * @param array<string, T> $map
     * @return list<T>
     */
    private function uniqueObjects(array $map): array
    {
        $seen = [];
        $result = [];
        foreach ($map as $object) {
            $id = spl_object_id($object);
            if (isset($seen[$id])) {
                continue;
            }
            $seen[$id] = true;
            $result[] = $object;
        }

        return $result;
    }
}
