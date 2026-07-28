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
        return $this->getMatchingRule($ruleNameOrOid)?->comparator;
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
     */
    public function merge(Schema $other): static
    {
        $merged = clone $this;
        foreach ($other->getAttributeTypes() as $type) {
            $merged->addAttributeType($type);
        }
        foreach ($other->getObjectClasses() as $class) {
            $merged->addObjectClass($class);
        }
        foreach ($other->getMatchingRules() as $rule) {
            $merged->addMatchingRule($rule);
        }
        foreach ($other->getLdapSyntaxes() as $syntax) {
            $merged->addSyntax($syntax);
        }

        return $merged;
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
