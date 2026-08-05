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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\ExtendedOperationRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Evaluates the configured {@see AclRules}; first matching rule wins, otherwise the rule set's default applies.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class RuleBasedAccessControl implements AccessControlInterface, BackendAwareInterface
{
    private AclRules $rules;

    public function __construct(?AclRules $rules = null)
    {
        $this->rules = $rules ?? AclRules::secureDefault();
    }

    public function setBackend(LdapBackendInterface $backend): void
    {
        $allRules = [
            ...$this->rules->operations,
            ...$this->rules->attributes,
            ...$this->rules->controls,
            ...$this->rules->extendedOps,
            ...$this->rules->confidential,
        ];

        foreach ($allRules as $rule) {
            if ($rule->subject instanceof BackendAwareInterface) {
                $rule->subject->setBackend($backend);
            }
        }
    }

    /**
     * @throws OperationException
     */
    public function authorizeOperation(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): void {
        if (!$this->isAllowed($operation, $token, $dn)) {
            $this->deny();
        }
    }

    /**
     * @throws OperationException
     */
    public function authorizeAttribute(
        TokenInterface $token,
        Dn $dn,
        string $attribute,
        AttributeAccess $access,
    ): void {
        $effect = $this->resolveAttributeEffect(
            $token,
            $dn,
            // Options are stripped here, so a rule on the base type cannot be sidestepped by naming one.
            Attribute::normalizeName($attribute),
            $access,
            $this->defaultEffectFor($access),
        );

        if ($effect === Effect::Deny) {
            $this->deny();
        }
    }

    /**
     * @throws OperationException
     */
    public function authorizeControl(
        TokenInterface $token,
        Dn $dn,
        string $controlOid,
    ): void {
        if (!$this->isControlAllowed($controlOid, $token, $dn)) {
            $this->deny();
        }
    }

    /**
     * @throws OperationException
     */
    public function authorizeExtendedOperation(
        TokenInterface $token,
        string $oid,
    ): void {
        if (!$this->isExtendedOperationAllowed($oid, $token)) {
            $this->deny();
        }
    }

    public function mayUseControl(
        TokenInterface $token,
        string $controlOid,
    ): bool {
        return $this->resolveSubjectEffect(
            $this->rules->controls,
            $this->controlMatches(...),
            $controlOid,
            $token,
            Effect::Deny,
        ) === Effect::Allow;
    }

    /**
     * Denied unless granted: a confidential attribute is withheld from anyone holding no rule for it.
     */
    public function hasConfidentialAccess(
        TokenInterface $token,
        string $attribute,
    ): bool {
        return $this->resolveSubjectEffect(
            $this->rules->confidential,
            $this->confidentialMatches(...),
            $attribute,
            $token,
            Effect::Deny,
        ) === Effect::Allow;
    }

    public function filterEntry(
        TokenInterface $token,
        Entry $entry,
    ): ?Entry {
        if (!$this->isEntryVisible($token, $entry)) {
            return null;
        }

        return $this->stripUnreadableAttributes(
            $token,
            $entry,
        );
    }

    public function stripUnreadableAttributes(
        TokenInterface $token,
        Entry $entry,
    ): Entry {
        $dn = $entry->getDn();

        if ($this->rules->attributes === []) {
            return $entry;
        }

        $allAttributes = $entry->getAttributes();
        $kept = [];

        foreach ($allAttributes as $attribute) {
            $effect = $this->resolveAttributeEffect(
                $token,
                $dn,
                strtolower($attribute->getName()),
                AttributeAccess::Read,
                Effect::Allow,
            );

            if ($effect !== Effect::Deny) {
                $kept[] = $attribute;
            }
        }

        if (count($kept) === count($allAttributes)) {
            return $entry;
        }

        return Entry::raw(
            $dn,
            $kept,
        );
    }

    public function isEntryVisible(
        TokenInterface $token,
        Entry $entry,
    ): bool {
        return $this->isAllowed(
            OperationType::Search,
            $token,
            $entry->getDn(),
        );
    }

    /**
     * Writes require a rule to permit them; reads are permitted unless a rule denies.
     */
    private function defaultEffectFor(AttributeAccess $access): Effect
    {
        return $access === AttributeAccess::Write
            ? Effect::Deny
            : Effect::Allow;
    }

    private function isAllowed(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): bool {
        return $this->resolveEffect(
            $this->rules->operations,
            $this->operationMatches(...),
            $operation,
            $token,
            $dn,
            Effect::Deny,
        ) === Effect::Allow;
    }

    private function operationMatches(
        OperationRule $rule,
        OperationType $operation,
    ): bool {
        return $rule->operations === []
            || in_array($operation, $rule->operations, true);
    }

    private function isControlAllowed(
        string $controlOid,
        TokenInterface $token,
        Dn $dn,
    ): bool {
        return $this->resolveEffect(
            $this->rules->controls,
            $this->controlMatches(...),
            $controlOid,
            $token,
            $dn,
            Effect::Deny,
        ) === Effect::Allow;
    }

    private function controlMatches(
        ControlRule $rule,
        string $controlOid,
    ): bool {
        return $rule->controlOids === []
            || in_array($controlOid, $rule->controlOids, true);
    }

    private function confidentialMatches(
        ConfidentialAccessRule $rule,
        string $attribute,
    ): bool {
        if ($rule->attributes === []) {
            return true;
        }

        foreach ($rule->attributes as $name) {
            if (strcasecmp($name, $attribute) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extended operations are target-independent, so the subject is matched against the token's own resolved DN.
     */
    private function isExtendedOperationAllowed(
        string $oid,
        TokenInterface $token,
    ): bool {
        return $this->resolveSubjectEffect(
            $this->rules->extendedOps,
            $this->extendedOperationMatches(...),
            $oid,
            $token,
            Effect::Deny,
        ) === Effect::Allow;
    }

    /**
     * The {@see resolveEffect} counterpart for rules carrying no target, so subjects that need one never match.
     * Anonymous identities never match, as they cannot hold a grant.
     *
     * @template TRule of ConfidentialAccessRule|ControlRule|ExtendedOperationRule
     * @template TValue
     * @param TRule[] $rules
     * @param callable(TRule, TValue): bool $selectorMatches
     * @param TValue $selectorValue
     */
    private function resolveSubjectEffect(
        array $rules,
        callable $selectorMatches,
        mixed $selectorValue,
        TokenInterface $token,
        Effect $default,
    ): Effect {
        if (!$token instanceof AuthenticatedTokenInterface) {
            return Effect::Deny;
        }

        foreach ($rules as $rule) {
            if (!$selectorMatches($rule, $selectorValue)) {
                continue;
            }

            if (!$rule->subject->matches($token, null)) {
                continue;
            }

            return $rule->effect;
        }

        return $default;
    }

    private function extendedOperationMatches(
        ExtendedOperationRule $rule,
        string $oid,
    ): bool {
        return $rule->extendedOpOids === []
            || in_array($oid, $rule->extendedOpOids, true);
    }

    /**
     * Returns the effect of the first rule whose selector, target, and subject all match; otherwise $default.
     *
     * @template TRule of OperationRule|ControlRule
     * @template TValue
     * @param TRule[] $rules
     * @param callable(TRule, TValue): bool $selectorMatches
     * @param TValue $selectorValue
     */
    private function resolveEffect(
        array $rules,
        callable $selectorMatches,
        mixed $selectorValue,
        TokenInterface $token,
        Dn $dn,
        Effect $default,
    ): Effect {
        foreach ($rules as $rule) {
            if (!$selectorMatches($rule, $selectorValue)) {
                continue;
            }

            if (!$rule->target->matches($dn)) {
                continue;
            }

            if (!$rule->subject->matches($token, $dn)) {
                continue;
            }

            return $rule->effect;
        }

        return $default;
    }

    private function resolveAttributeEffect(
        TokenInterface $token,
        Dn $dn,
        string $attrName,
        AttributeAccess $access,
        Effect $default,
    ): Effect {
        foreach ($this->rules->attributes as $rule) {
            if (!$rule->access->includes($access)) {
                continue;
            }

            if (!$rule->target->matches($dn)) {
                continue;
            }

            if (!$rule->subject->matches($token, $dn)) {
                continue;
            }

            if ($rule->attributes !== [] && !in_array($attrName, $rule->attributes, true)) {
                continue;
            }

            return $rule->effect;
        }

        return $default;
    }

    /**
     * @throws OperationException
     */
    private function deny(): never
    {
        throw new OperationException(
            'Access denied.',
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
        );
    }
}
