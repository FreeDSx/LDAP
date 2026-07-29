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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\Rule\ExtendedOperationRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\TargetMatcherInterface;

/**
 * The rule sets and defaults that configure {@see RuleBasedAccessControl}.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AclRules
{
    /**
     * @param OperationRule[] $operations Evaluated in order; first match wins.
     * @param AttributeRule[] $attributes Evaluated per attribute in order; first match wins.
     * @param ControlRule[] $controls Evaluated per control in order; first match wins.
     * @param ExtendedOperationRule[] $extendedOps Evaluated per extended operation in order; first match wins.
     * @param ConfidentialAccessRule[] $confidential Evaluated per confidential attribute in order; first match wins.
     * @param Effect $defaultOperationEffect Applied when no operation rule matches.
     * @param Effect $defaultControlEffect Applied when no control rule matches (controls are gated, so Deny).
     * @param Effect $defaultExtendedOpEffect Applied when no extended-operation rule matches (gated, so Deny).
     */
    private function __construct(
        public array $operations = [],
        public array $attributes = [],
        public array $controls = [],
        public array $extendedOps = [],
        public array $confidential = [],
        public Effect $defaultOperationEffect = Effect::Deny,
        public Effect $defaultControlEffect = Effect::Deny,
        public Effect $defaultExtendedOpEffect = Effect::Deny,
    ) {}

    /**
     * A blank ruleset (deny-by-default) to build up with the with* methods.
     *
     * Unlike secureDefault() it adds no credential protection, so any userPassword rule is yours to add.
     *
     * @param OperationRule[] $operations
     * @param AttributeRule[] $attributes
     * @param ControlRule[] $controls
     * @param ExtendedOperationRule[] $extendedOps
     * @param ConfidentialAccessRule[] $confidential
     */
    public static function fromEmpty(
        array $operations = [],
        array $attributes = [],
        array $controls = [],
        array $extendedOps = [],
        array $confidential = [],
        Effect $defaultOperationEffect = Effect::Deny,
        Effect $defaultControlEffect = Effect::Deny,
        Effect $defaultExtendedOpEffect = Effect::Deny,
    ): self {
        return new self(
            $operations,
            $attributes,
            $controls,
            $extendedOps,
            $confidential,
            $defaultOperationEffect,
            $defaultControlEffect,
            $defaultExtendedOpEffect,
        );
    }

    public function withOperationRules(OperationRule ...$operations): self
    {
        return new self(
            $operations,
            $this->attributes,
            $this->controls,
            $this->extendedOps,
            $this->confidential,
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
            $this->defaultExtendedOpEffect,
        );
    }

    public function withAttributeRules(AttributeRule ...$attributes): self
    {
        return new self(
            $this->operations,
            $attributes,
            $this->controls,
            $this->extendedOps,
            $this->confidential,
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
            $this->defaultExtendedOpEffect,
        );
    }

    public function withControlRules(ControlRule ...$controls): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $controls,
            $this->extendedOps,
            $this->confidential,
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
            $this->defaultExtendedOpEffect,
        );
    }

    public function withExtendedOperationRules(ExtendedOperationRule ...$extendedOps): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $extendedOps,
            $this->confidential,
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
            $this->defaultExtendedOpEffect,
        );
    }

    /**
     * Rules gating reads of schema attributes marked X-CONFIDENTIAL; nothing may read them without a grant.
     */
    public function withConfidentialAccess(ConfidentialAccessRule ...$confidential): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $this->extendedOps,
            $confidential,
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
            $this->defaultExtendedOpEffect,
        );
    }

    /**
     * Grant a replica's bind identity the privileged capabilities it needs: the content-sync control over $target,
     * the password-policy forward extended operation, and confidential attributes so those replicate.
     */
    public function withReplicaGrants(
        SubjectMatcherInterface $replica,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
    ): self {
        return new self(
            $this->operations,
            $this->attributes,
            [
                ...$this->controls,
                ControlRule::allow(
                    $replica,
                    $target,
                    Control::OID_SYNC_REQUEST,
                ),
            ],
            [
                ...$this->extendedOps,
                ExtendedOperationRule::allow(
                    $replica,
                    ExtendedRequest::OID_PPOLICY_STATE_FORWARD,
                ),
            ],
            [
                ...$this->confidential,
                ConfidentialAccessRule::allowAny($replica),
            ],
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
            $this->defaultExtendedOpEffect,
        );
    }

    public function withDefaultOperationEffect(Effect $effect): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $this->extendedOps,
            $this->confidential,
            $effect,
            $this->defaultControlEffect,
            $this->defaultExtendedOpEffect,
        );
    }

    public function withDefaultControlEffect(Effect $effect): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $this->extendedOps,
            $this->confidential,
            $this->defaultOperationEffect,
            $effect,
            $this->defaultExtendedOpEffect,
        );
    }

    public function withDefaultExtendedOpEffect(Effect $effect): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $this->extendedOps,
            $this->confidential,
            $this->defaultOperationEffect,
            $this->defaultControlEffect,
            $effect,
        );
    }

    /**
     * The secure default.
     *
     * @see self::withCredentialProtection()
     */
    public static function secureDefault(?SubjectMatcherInterface $administrators = null): self
    {
        $base = new self(operations: [OperationRule::allow(Subject::authenticated())]);

        return $base->withCredentialProtection($administrators);
    }

    /**
     * Prepend the credential-protection rules to this rule set so they take precedence (first match wins):
     *
     * - userPassword is writable by self and the administrator, and readable by no one.
     * - PasswordModify is permitted for self and the administrator, denied to everyone else.
     * - Privileged controls are allowed to the administrator (otherwise the default deny applies).
     * - Privileged extended operations are allowed to the administrator (otherwise the default deny applies).
     */
    public function withCredentialProtection(?SubjectMatcherInterface $administrators = null): self
    {
        $anyTarget = new AnyTargetMatcher();

        $passwordModify = [
            OperationRule::allow(
                Subject::self(),
                $anyTarget,
                OperationType::PasswordModify,
            ),
        ];
        $userPassword = [
            AttributeRule::allow(
                Subject::self(),
                $anyTarget,
                'userPassword',
            )->forWrite(),
        ];
        $controls = [];
        $extendedOps = [];

        if ($administrators !== null) {
            $passwordModify[] = OperationRule::allow(
                $administrators,
                $anyTarget,
                OperationType::PasswordModify,
            );
            $userPassword[] = AttributeRule::allow(
                $administrators,
                $anyTarget,
                'userPassword',
            )->forWrite();
            $controls[] = ControlRule::allow($administrators);
            $extendedOps[] = ExtendedOperationRule::allow($administrators);
        }

        $passwordModify[] = OperationRule::deny(
            Subject::anyone(),
            $anyTarget,
            OperationType::PasswordModify,
        );
        $userPassword[] = AttributeRule::deny(
            Subject::anyone(),
            $anyTarget,
            'userPassword',
        )->forWrite();
        $userPassword[] = AttributeRule::deny(
            Subject::anyone(),
            $anyTarget,
            'userPassword',
        )->forRead();

        return new self(
            operations: [...$passwordModify, ...$this->operations],
            attributes: [...$userPassword, ...$this->attributes],
            controls: [...$controls, ...$this->controls],
            extendedOps: [...$extendedOps, ...$this->extendedOps],
            confidential: $this->confidential,
            defaultOperationEffect: $this->defaultOperationEffect,
            defaultControlEffect: $this->defaultControlEffect,
            defaultExtendedOpEffect: $this->defaultExtendedOpEffect,
        );
    }
}
