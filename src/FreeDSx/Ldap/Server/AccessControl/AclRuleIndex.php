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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;

use function array_filter;
use function array_values;
use function in_array;

/**
 * Attribute and operation rules grouped by what they select.
 *
 * @internal
 */
readonly class AclRuleIndex
{
    /**
     * @param array<string, array<string, list<AttributeRule>>> $namedAttributeRules Keyed by access case, then name.
     * @param array<string, list<AttributeRule>> $anyAttributeRules Rules naming no attribute, keyed by access case.
     * @param array<string, list<OperationRule>> $operationRules Keyed by operation type.
     */
    private function __construct(
        private array $namedAttributeRules,
        private array $anyAttributeRules,
        private array $operationRules,
    ) {}

    public static function of(AclRules $rules): self
    {
        $named = [];
        $any = [];
        $operations = [];

        foreach (AttributeAccess::cases() as $access) {
            $applicable = array_values(array_filter(
                $rules->attributes,
                static fn(AttributeRule $rule): bool => $rule->access->includes($access),
            ));
            $named[$access->name] = self::byName($applicable);
            $any[$access->name] = self::naming(
                $applicable,
                null,
            );
        }

        foreach (OperationType::cases() as $operation) {
            $operations[$operation->value] = array_values(array_filter(
                $rules->operations,
                static fn(OperationRule $rule): bool => $rule->operations === []
                    || in_array($operation, $rule->operations, true),
            ));
        }

        return new self(
            $named,
            $any,
            $operations,
        );
    }

    /**
     * The rules that could decide this access to an attribute, by its lowercased base name.
     *
     * @return list<AttributeRule>
     */
    public function attributeRules(
        AttributeAccess $access,
        string $attributeName,
    ): array {
        return $this->namedAttributeRules[$access->name][$attributeName]
            ?? $this->anyAttributeRules[$access->name];
    }

    /**
     * @return list<OperationRule>
     */
    public function operationRules(OperationType $operation): array
    {
        return $this->operationRules[$operation->value];
    }

    /**
     * @param list<AttributeRule> $rules
     *
     * @return array<string, list<AttributeRule>>
     */
    private static function byName(array $rules): array
    {
        $byName = [];

        foreach ($rules as $rule) {
            foreach ($rule->attributes as $name) {
                $byName[$name] ??= self::naming(
                    $rules,
                    $name,
                );
            }
        }

        return $byName;
    }

    /**
     * The rules applying to one name, or to any name when null. This keeps a rule naming no attribute in both cases.
     *
     * @param list<AttributeRule> $rules
     *
     * @return list<AttributeRule>
     */
    private static function naming(
        array $rules,
        ?string $name,
    ): array {
        return array_values(array_filter(
            $rules,
            static fn(AttributeRule $rule): bool => $rule->attributes === []
                || ($name !== null && in_array($name, $rule->attributes, true)),
        ));
    }
}
