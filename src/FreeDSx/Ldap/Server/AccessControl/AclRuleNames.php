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

use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\FilterAccessRule;

use function array_map;
use function array_values;

/**
 * Spells the attributes access control rules name by their primary schema names, so any spelling of one matches.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AclRuleNames
{
    public function __construct(
        private Schema $schema,
    ) {}

    public function canonicalize(AclRules $rules): AclRules
    {
        return $rules
            ->replaceAttributeRules(...array_map(
                $this->attributeRule(...),
                $rules->attributes,
            ))
            ->replaceConfidentialAccess(...array_map(
                $this->confidentialRule(...),
                $rules->confidential,
            ))
            ->replaceFilterAccess(...array_map(
                $this->filterRule(...),
                $rules->filters,
            ));
    }

    private function attributeRule(AttributeRule $rule): AttributeRule
    {
        return new AttributeRule(
            $rule->effect,
            $rule->subject,
            $rule->target,
            $this->names($rule->attributes),
            $rule->access,
        );
    }

    private function confidentialRule(ConfidentialAccessRule $rule): ConfidentialAccessRule
    {
        return $rule->effect === Effect::Allow
            ? ConfidentialAccessRule::allow(
                $rule->subject,
                ...$this->names($rule->attributes),
            )
            : ConfidentialAccessRule::deny(
                $rule->subject,
                ...$this->names($rule->attributes),
            );
    }

    private function filterRule(FilterAccessRule $rule): FilterAccessRule
    {
        return $rule->effect === Effect::Allow
            ? FilterAccessRule::allow(
                $rule->subject,
                ...$this->names($rule->attributes),
            )
            : FilterAccessRule::deny(
                $rule->subject,
                ...$this->names($rule->attributes),
            );
    }

    /**
     * @param string[] $names
     * @return list<string>
     */
    private function names(array $names): array
    {
        return array_values(array_map(
            $this->schema->canonicalAttributeName(...),
            $names,
        ));
    }
}
