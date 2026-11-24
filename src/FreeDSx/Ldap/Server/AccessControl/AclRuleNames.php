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

use FreeDSx\Ldap\Schema\AttributeTypeSpelling;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\ExtendedOperationRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\FilterAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\RelocationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\AccessControl\Target\TargetMatcherInterface;
use WeakMap;

use function array_map;
use function array_values;

/**
 * Spells the attributes and DNs access control rules name by their primary schema names, letting any spelling match.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AclRuleNames
{
    /**
     * @var WeakMap<SubjectMatcherInterface, SubjectMatcherInterface>
     */
    private WeakMap $subjects;

    public function __construct(
        private Schema $schema,
        private AttributeTypeSpelling $spelling,
    ) {
        $this->subjects = new WeakMap();
    }

    public function canonicalize(AclRules $rules): AclRules
    {
        return $rules
            ->replaceOperationRules(...array_map(
                $this->operationRule(...),
                $rules->operations,
            ))
            ->replaceAttributeRules(...array_map(
                $this->attributeRule(...),
                $rules->attributes,
            ))
            ->replaceControlRules(...array_map(
                $this->controlRule(...),
                $rules->controls,
            ))
            ->replaceExtendedOperationRules(...array_map(
                $this->extendedOperationRule(...),
                $rules->extendedOps,
            ))
            ->replaceConfidentialAccess(...array_map(
                $this->confidentialRule(...),
                $rules->confidential,
            ))
            ->replaceRelocationRules(...array_map(
                $this->relocationRule(...),
                $rules->relocations,
            ))
            ->replaceFilterAccess(...array_map(
                $this->filterRule(...),
                $rules->filters,
            ));
    }

    /**
     * One subject respells to one shared copy, keeping a group's backend and membership reads common to every rule.
     */
    public function subject(SubjectMatcherInterface $subject): SubjectMatcherInterface
    {
        if (!$subject instanceof DnSpellableInterface) {
            return $subject;
        }

        $spelled = $this->subjects[$subject] ?? $subject->spelledBy($this->spelling);

        // A subject mapped to itself would keep its own entry alive.
        if ($spelled !== $subject) {
            $this->subjects[$subject] = $spelled;
        }

        return $spelled;
    }

    private function target(TargetMatcherInterface $target): TargetMatcherInterface
    {
        return $target instanceof DnSpellableInterface
            ? $target->spelledBy($this->spelling)
            : $target;
    }

    private function operationRule(OperationRule $rule): OperationRule
    {
        $subject = $this->subject($rule->subject);
        $target = $this->target($rule->target);

        if ($subject === $rule->subject && $target === $rule->target) {
            return $rule;
        }

        return new OperationRule(
            $rule->effect,
            $subject,
            $target,
            $rule->operations,
        );
    }

    private function attributeRule(AttributeRule $rule): AttributeRule
    {
        return new AttributeRule(
            $rule->effect,
            $this->subject($rule->subject),
            $this->target($rule->target),
            $this->names($rule->attributes),
            $rule->access,
        );
    }

    private function controlRule(ControlRule $rule): ControlRule
    {
        $subject = $this->subject($rule->subject);
        $target = $this->target($rule->target);

        if ($subject === $rule->subject && $target === $rule->target) {
            return $rule;
        }

        return new ControlRule(
            $rule->effect,
            $subject,
            $target,
            $rule->controlOids,
        );
    }

    private function extendedOperationRule(ExtendedOperationRule $rule): ExtendedOperationRule
    {
        $subject = $this->subject($rule->subject);

        if ($subject === $rule->subject) {
            return $rule;
        }

        return new ExtendedOperationRule(
            $rule->effect,
            $subject,
            $rule->extendedOpOids,
        );
    }

    private function confidentialRule(ConfidentialAccessRule $rule): ConfidentialAccessRule
    {
        return $rule->effect === Effect::Allow
            ? ConfidentialAccessRule::allow(
                $this->subject($rule->subject),
                ...$this->names($rule->attributes),
            )
            : ConfidentialAccessRule::deny(
                $this->subject($rule->subject),
                ...$this->names($rule->attributes),
            );
    }

    private function relocationRule(RelocationRule $rule): RelocationRule
    {
        $subject = $this->subject($rule->subject);
        $target = $this->target($rule->target);

        if ($subject === $rule->subject && $target === $rule->target) {
            return $rule;
        }

        return new RelocationRule(
            $rule->effect,
            $subject,
            $target,
            $rule->access,
        );
    }

    private function filterRule(FilterAccessRule $rule): FilterAccessRule
    {
        return $rule->effect === Effect::Allow
            ? FilterAccessRule::allow(
                $this->subject($rule->subject),
                ...$this->names($rule->attributes),
            )
            : FilterAccessRule::deny(
                $this->subject($rule->subject),
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
