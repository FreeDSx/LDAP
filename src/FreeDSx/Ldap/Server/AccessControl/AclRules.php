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
     * Personal attributes an identity may change on its own entry, so callers can extend rather than retype them.
     *
     * @var list<string>
     *
     * @see self::withSelfServiceWrites()
     */
    public const SELF_WRITABLE_ATTRIBUTES = [
        'description',
        'displayName',
        'givenName',
        'initials',
        'jpegPhoto',
        'labeledURI',
    ];

    /**
     * @param OperationRule[] $operations Evaluated in order; first match wins.
     * @param AttributeRule[] $attributes Evaluated per attribute in order; first match wins.
     * @param ControlRule[] $controls Evaluated per control in order; first match wins.
     * @param ExtendedOperationRule[] $extendedOps Evaluated per extended operation in order; first match wins.
     * @param ConfidentialAccessRule[] $confidential Evaluated per confidential attribute in order; first match wins.
     */
    private function __construct(
        public array $operations = [],
        public array $attributes = [],
        public array $controls = [],
        public array $extendedOps = [],
        public array $confidential = [],
    ) {}

    /**
     * A blank ruleset to build up with the with* methods; anything left unmatched is denied.
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
    ): self {
        return new self(
            $operations,
            $attributes,
            $controls,
            $extendedOps,
            $confidential,
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
        );
    }

    /**
     * The secure default. Reads are open to authenticated identities, writes require a grant:
     *
     * - Search and Compare are allowed to any authenticated identity, on any entry.
     * - An identity may Modify its own entry, limited to a set of personal attributes.
     * - Everything else is left to the administrator, when one is configured.
     *
     * Nothing can grant itself group membership or edit another entry without an explicit rule.
     *
     * @param list<string> $selfWritableAttributes Attributes an identity may change on its own entry.
     *
     * @see self::withSelfServiceWrites()
     * @see self::withCredentialProtection()
     */
    public static function secureDefault(
        ?SubjectMatcherInterface $administrators = null,
        array $selfWritableAttributes = self::SELF_WRITABLE_ATTRIBUTES,
    ): self {
        $anyTarget = new AnyTargetMatcher();

        $rules = self::fromEmpty(
            operations: [
                OperationRule::allow(
                    Subject::authenticated(),
                    $anyTarget,
                    OperationType::Search,
                    OperationType::Compare,
                ),
            ],
        )->withSelfServiceWrites($selfWritableAttributes);

        if ($administrators !== null) {
            $rules = $rules->withFullAccess($administrators);
        }

        return $rules->withCredentialProtection($administrators);
    }

    /**
     * Append a grant of every operation and every attribute write for a subject over $target.
     *
     * Controls, extended operations, and confidential attributes are gated separately and are not included.
     *
     * @see self::withCredentialProtection()
     * @see self::withConfidentialAccess()
     */
    public function withFullAccess(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
    ): self {
        return new self(
            operations: [
                ...$this->operations,
                OperationRule::allow(
                    $subject,
                    $target,
                ),
            ],
            attributes: [
                ...$this->attributes,
                AttributeRule::allow(
                    $subject,
                    $target,
                )->forWrite(),
            ],
            controls: $this->controls,
            extendedOps: $this->extendedOps,
            confidential: $this->confidential,
        );
    }

    /**
     * Append the self-service rules to this rule set, letting an identity modify its own entry.
     *
     * The default set leaves out anything carrying authorization, identity, or account recovery, since self-service
     * on those is a route to escalation or account takeover. Widen it only with that in mind.
     *
     * @param list<string> $attributes Attributes writable on one's own entry; an empty list grants no attribute write.
     */
    public function withSelfServiceWrites(array $attributes = self::SELF_WRITABLE_ATTRIBUTES): self
    {
        $anyTarget = new AnyTargetMatcher();

        // An AttributeRule with no attributes named matches every attribute, so an empty list must add no rule at all.
        $selfWrites = $attributes === []
            ? []
            : [
                AttributeRule::allow(
                    Subject::self(),
                    $anyTarget,
                    ...$attributes,
                )->forWrite(),
            ];

        return new self(
            operations: [
                ...$this->operations,
                OperationRule::allow(
                    Subject::self(),
                    $anyTarget,
                    OperationType::Modify,
                ),
            ],
            attributes: [
                ...$this->attributes,
                ...$selfWrites,
            ],
            controls: $this->controls,
            extendedOps: $this->extendedOps,
            confidential: $this->confidential,
        );
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
        );
    }
}
