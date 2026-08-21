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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerMonitorHandler;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ExtendedOperationRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\RelocationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\DnTargetMatcher;
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
     * @param RelocationRule[] $relocations Evaluated per container and direction in order; first match wins.
     */
    private function __construct(
        public array $operations = [],
        public array $attributes = [],
        public array $controls = [],
        public array $extendedOps = [],
        public array $confidential = [],
        public array $relocations = [],
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
     * @param RelocationRule[] $relocations
     */
    public static function fromEmpty(
        array $operations = [],
        array $attributes = [],
        array $controls = [],
        array $extendedOps = [],
        array $confidential = [],
        array $relocations = [],
    ): self {
        return new self(
            $operations,
            $attributes,
            $controls,
            $extendedOps,
            $confidential,
            $relocations,
        );
    }

    /**
     * Discards every operation rule already present, including any the secure default installed.
     */
    public function replaceOperationRules(OperationRule ...$operations): self
    {
        return new self(
            $operations,
            $this->attributes,
            $this->controls,
            $this->extendedOps,
            $this->confidential,
            $this->relocations,
        );
    }

    /**
     * Discards every attribute rule already present, including the credential protection of the secure default.
     */
    public function replaceAttributeRules(AttributeRule ...$attributes): self
    {
        return new self(
            $this->operations,
            $attributes,
            $this->controls,
            $this->extendedOps,
            $this->confidential,
            $this->relocations,
        );
    }

    /**
     * Discards every control rule already present, including any the secure default installed.
     */
    public function replaceControlRules(ControlRule ...$controls): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $controls,
            $this->extendedOps,
            $this->confidential,
            $this->relocations,
        );
    }

    /**
     * Discards every extended operation rule already present, including any the secure default installed.
     */
    public function replaceExtendedOperationRules(ExtendedOperationRule ...$extendedOps): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $extendedOps,
            $this->confidential,
            $this->relocations,
        );
    }

    /**
     * Rules gating reads of schema attributes marked X-CONFIDENTIAL; nothing may read them without a grant.
     *
     * Discards every confidential rule already present.
     */
    public function replaceConfidentialAccess(ConfidentialAccessRule ...$confidential): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $this->extendedOps,
            $confidential,
            $this->relocations,
        );
    }

    /**
     * Rules gating whether entries may leave or arrive in a container, consulted only when a move changes the parent.
     *
     * Discards every relocation rule already present.
     */
    public function replaceRelocationRules(RelocationRule ...$relocations): self
    {
        return new self(
            $this->operations,
            $this->attributes,
            $this->controls,
            $this->extendedOps,
            $this->confidential,
            $relocations,
        );
    }

    /**
     * Append operation rules, so anything already present matches first.
     */
    public function appendOperationRules(OperationRule ...$operations): self
    {
        return $this->replaceOperationRules(
            ...$this->operations,
            ...$operations,
        );
    }

    /**
     * Append attribute rules, so anything already present matches first.
     */
    public function appendAttributeRules(AttributeRule ...$attributes): self
    {
        return $this->replaceAttributeRules(
            ...$this->attributes,
            ...$attributes,
        );
    }

    /**
     * Append control rules, so anything already present matches first.
     */
    public function appendControlRules(ControlRule ...$controls): self
    {
        return $this->replaceControlRules(
            ...$this->controls,
            ...$controls,
        );
    }

    /**
     * Append extended operation rules, so anything already present matches first.
     */
    public function appendExtendedOperationRules(ExtendedOperationRule ...$extendedOps): self
    {
        return $this->replaceExtendedOperationRules(
            ...$this->extendedOps,
            ...$extendedOps,
        );
    }

    /**
     * Append confidential access rules, so anything already present matches first.
     */
    public function appendConfidentialAccess(ConfidentialAccessRule ...$confidential): self
    {
        return $this->replaceConfidentialAccess(
            ...$this->confidential,
            ...$confidential,
        );
    }

    /**
     * Append relocation rules, so anything already present matches first.
     */
    public function appendRelocationRules(RelocationRule ...$relocations): self
    {
        return $this->replaceRelocationRules(
            ...$this->relocations,
            ...$relocations,
        );
    }

    /**
     * Prepend operation rules, so these match ahead of anything already present.
     */
    public function prependOperationRules(OperationRule ...$operations): self
    {
        return $this->replaceOperationRules(
            ...$operations,
            ...$this->operations,
        );
    }

    /**
     * Prepend attribute rules, so these match ahead of anything already present.
     */
    public function prependAttributeRules(AttributeRule ...$attributes): self
    {
        return $this->replaceAttributeRules(
            ...$attributes,
            ...$this->attributes,
        );
    }

    /**
     * Prepend control rules, so these match ahead of anything already present.
     */
    public function prependControlRules(ControlRule ...$controls): self
    {
        return $this->replaceControlRules(
            ...$controls,
            ...$this->controls,
        );
    }

    /**
     * Prepend extended operation rules, so these match ahead of anything already present.
     */
    public function prependExtendedOperationRules(ExtendedOperationRule ...$extendedOps): self
    {
        return $this->replaceExtendedOperationRules(
            ...$extendedOps,
            ...$this->extendedOps,
        );
    }

    /**
     * Prepend confidential access rules, so these match ahead of anything already present.
     */
    public function prependConfidentialAccess(ConfidentialAccessRule ...$confidential): self
    {
        return $this->replaceConfidentialAccess(
            ...$confidential,
            ...$this->confidential,
        );
    }

    /**
     * Grant a replica's bind identity the privileged capabilities it needs: the content-sync control over $target and
     * the password-policy forward extended operation.
     *
     * $target bounds both what may be synced and which entries policy state may be forwarded for. No attribute read
     * grant is needed, since a sync ships visible entries whole. This is intentional for replication to work properly.
     */
    public function withReplicaGrants(
        SubjectMatcherInterface $replica,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
    ): self {
        return $this
            ->appendControlRules(ControlRule::allow(
                $replica,
                $target,
                Control::OID_SYNC_REQUEST,
            ))
            ->appendExtendedOperationRules(ExtendedOperationRule::allow(
                $replica,
                ExtendedRequest::OID_PPOLICY_STATE_FORWARD,
            ))
            // The extended operation carries no target, so the entries it may be forwarded for are bounded here.
            ->appendAttributeRules(AttributeRule::allow(
                $replica,
                $target,
                PasswordPolicyOid::NAME_PWD_FAILURE_TIME,
                PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
                PasswordPolicyOid::NAME_PWD_LAST_SUCCESS,
            )->forWrite());
    }

    /**
     * The secure default. Reads are open to authenticated identities, writes require a grant:
     *
     * - Search and Compare are allowed to any authenticated identity, on any entry.
     * - cn=monitor is limited to the administrator.
     * - An identity may Modify its own entry, limited to a set of personal attributes.
     * - Everything else is left to the administrator, when one is configured.
     *
     * Nothing can grant itself group membership or edit another entry without an explicit rule.
     *
     * @param list<string> $selfWritableAttributes Attributes an identity may change on its own entry.
     *
     * @see self::withSelfServiceWrites()
     * @see self::withMonitorAccess()
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

        return $rules
            ->withMonitorAccess($administrators)
            ->withCredentialProtection($administrators);
    }

    /**
     * Append a grant of every operation and every attribute write for a subject over $target.
     *
     * Controls, extended operations, and confidential attributes are gated separately and are not included.
     *
     * @see self::withCredentialProtection()
     * @see self::replaceConfidentialAccess()
     */
    public function withFullAccess(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
    ): self {
        return $this
            ->appendOperationRules(OperationRule::allow(
                $subject,
                $target,
            ))
            ->appendAttributeRules(AttributeRule::allow(
                $subject,
                $target,
            )->forWrite())
            ->appendRelocationRules(RelocationRule::allow(
                $subject,
                $target,
            ));
    }

    /**
     * Restrict searches of the subschema subentry to $subject, replacing any earlier rule for that entry.
     */
    public function withSubschemaAccess(
        SubjectMatcherInterface $subject,
        Dn $subschemaEntry,
    ): self {
        return $this->withGeneratedEntryAccess(
            $subschemaEntry,
            $subject,
        );
    }

    /**
     * Restrict searches of cn=monitor to $subject, or to nobody when it is null.
     */
    public function withMonitorAccess(?SubjectMatcherInterface $subject): self
    {
        return $this->withGeneratedEntryAccess(
            new Dn(ServerMonitorHandler::DN),
            $subject,
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

        return $this
            ->appendOperationRules(OperationRule::allow(
                Subject::self(),
                $anyTarget,
                OperationType::Modify,
            ))
            ->appendAttributeRules(...$selfWrites);
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

        return $this
            ->prependOperationRules(...$passwordModify)
            ->prependAttributeRules(...$userPassword)
            ->prependControlRules(...$controls)
            ->prependExtendedOperationRules(...$extendedOps);
    }

    /**
     * Prepend an allow plus a catch-all deny for one entry, so first-match-wins makes this authoritative.
     */
    private function withGeneratedEntryAccess(
        Dn $dn,
        ?SubjectMatcherInterface $subject,
    ): self {
        $target = new DnTargetMatcher($dn->toString());

        $grant = $subject === null
            ? []
            : [
                OperationRule::allow(
                    $subject,
                    $target,
                    OperationType::Search,
                ),
            ];

        return $this->prependOperationRules(
            ...$grant,
            ...[OperationRule::deny(
                Subject::anyone(),
                $target,
                OperationType::Search,
            )],
        );
    }
}
