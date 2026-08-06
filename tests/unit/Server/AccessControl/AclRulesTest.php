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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerMonitorHandler;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;

final class AclRulesTest extends TestCase
{
    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private const OTHER_DN = 'cn=other,dc=foo,dc=bar';

    private const ADMIN_DN = 'cn=admin,dc=foo,dc=bar';

    private RuleBasedAccessControl $subject;

    protected function setUp(): void
    {
        $this->subject = new RuleBasedAccessControl(
            AclRules::secureDefault(Subject::dn(self::ADMIN_DN)),
        );
    }

    public function test_secureDefault_lets_self_write_its_own_userPassword(): void
    {
        $this->subject->authorizeAttribute(
            $this->user(),
            new Dn(self::USER_DN),
            'userPassword',
            AttributeAccess::Write,
        );

        $this->addToAssertionCount(1);
    }

    public function test_withReplicaGrants_allows_the_sync_control_and_forward_op(): void
    {
        $rules = AclRules::fromEmpty()->withReplicaGrants(Subject::dn('cn=replica,dc=foo,dc=bar'));

        $control = $rules->controls[0];
        self::assertSame(
            Effect::Allow,
            $control->effect,
        );
        self::assertContains(
            Control::OID_SYNC_REQUEST,
            $control->controlOids,
        );

        $extendedOp = $rules->extendedOps[0];
        self::assertSame(
            Effect::Allow,
            $extendedOp->effect,
        );
        self::assertContains(
            ExtendedRequest::OID_PPOLICY_STATE_FORWARD,
            $extendedOp->extendedOpOids,
        );
    }

    /**
     * The forward operation carries no target of its own, so the same target bounds which entries it may reach.
     */
    public function test_withReplicaGrants_scopes_the_forwarded_policy_writes_to_its_target(): void
    {
        $replica = BindToken::fromSasl(
            'replica',
            new Dn('cn=replica,dc=foo,dc=bar'),
        );
        $accessControl = new RuleBasedAccessControl(
            AclRules::fromEmpty()->withReplicaGrants(
                Subject::dn('cn=replica,dc=foo,dc=bar'),
                Target::subtree('ou=replicated,dc=foo,dc=bar'),
            ),
        );

        $accessControl->authorizeAttribute(
            $replica,
            new Dn('cn=bob,ou=replicated,dc=foo,dc=bar'),
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
            AttributeAccess::Write,
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $accessControl->authorizeAttribute(
            $replica,
            new Dn('cn=admin,dc=foo,dc=bar'),
            PasswordPolicyOid::NAME_PWD_ACCOUNT_LOCKED_TIME,
            AttributeAccess::Write,
        );
    }

    public function test_withReplicaGrants_allows_confidential_attributes_so_those_replicate(): void
    {
        $rules = AclRules::fromEmpty()->withReplicaGrants(Subject::dn('cn=replica,dc=foo,dc=bar'));

        $confidential = $rules->confidential[0];
        self::assertSame(
            Effect::Allow,
            $confidential->effect,
        );
        // An empty attribute list covers every confidential attribute, not none of them.
        self::assertSame(
            [],
            $confidential->attributes,
        );
    }

    public function test_withCredentialProtection_keeps_confidential_grants_made_earlier(): void
    {
        $rules = AclRules::fromEmpty()
            ->withReplicaGrants(Subject::dn('cn=replica,dc=foo,dc=bar'))
            ->withCredentialProtection();

        self::assertCount(
            1,
            $rules->confidential,
        );
    }

    public function test_withReplicaGrants_appends_to_existing_control_rules(): void
    {
        $existing = ControlRule::allow(Subject::dn(self::ADMIN_DN));
        $rules = AclRules::fromEmpty(controls: [$existing])
            ->withReplicaGrants(Subject::dn('cn=replica,dc=foo,dc=bar'));

        self::assertSame(
            $existing,
            $rules->controls[0],
        );
        self::assertCount(
            2,
            $rules->controls,
        );
    }

    public function test_secureDefault_denies_writing_another_userPassword(): void
    {
        $this->expectException(OperationException::class);

        $this->subject->authorizeAttribute(
            $this->user(),
            new Dn(self::OTHER_DN),
            'userPassword',
            AttributeAccess::Write,
        );
    }

    public function test_secureDefault_lets_admin_write_another_userPassword(): void
    {
        $this->subject->authorizeAttribute(
            $this->admin(),
            new Dn(self::OTHER_DN),
            'userPassword',
            AttributeAccess::Write,
        );

        $this->addToAssertionCount(1);
    }

    public function test_secureDefault_restricts_passwordModify_to_self_or_admin(): void
    {
        $this->subject->authorizeOperation(
            OperationType::PasswordModify,
            $this->user(),
            new Dn(self::USER_DN),
        );
        $this->subject->authorizeOperation(
            OperationType::PasswordModify,
            $this->admin(),
            new Dn(self::OTHER_DN),
        );

        $this->expectException(OperationException::class);
        $this->subject->authorizeOperation(
            OperationType::PasswordModify,
            $this->user(),
            new Dn(self::OTHER_DN),
        );
    }

    public function test_secureDefault_allows_authenticated_reads_of_any_entry(): void
    {
        $this->subject->authorizeOperation(
            OperationType::Search,
            $this->user(),
            new Dn(self::OTHER_DN),
        );
        $this->subject->authorizeOperation(
            OperationType::Compare,
            $this->user(),
            new Dn(self::OTHER_DN),
        );

        $this->addToAssertionCount(1);
    }

    public function test_secureDefault_allows_an_identity_to_modify_its_own_entry(): void
    {
        $this->subject->authorizeOperation(
            OperationType::Modify,
            $this->user(),
            new Dn(self::USER_DN),
        );

        $this->addToAssertionCount(1);
    }

    public function test_secureDefault_denies_modifying_another_entry(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeOperation(
            OperationType::Modify,
            $this->user(),
            new Dn(self::OTHER_DN),
        );
    }

    /**
     * Writing member on a group entry would otherwise let an identity grant itself that group's rules.
     */
    public function test_secureDefault_denies_granting_yourself_group_membership(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeAttribute(
            $this->user(),
            new Dn('cn=admins,dc=foo,dc=bar'),
            'member',
            AttributeAccess::Write,
        );
    }

    public function test_secureDefault_allows_self_service_on_personal_attributes(): void
    {
        $this->subject->authorizeAttribute(
            $this->user(),
            new Dn(self::USER_DN),
            'displayName',
            AttributeAccess::Write,
        );

        $this->addToAssertionCount(1);
    }

    public function test_secureDefault_denies_self_service_on_anything_else(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeAttribute(
            $this->user(),
            new Dn(self::USER_DN),
            'mail',
            AttributeAccess::Write,
        );
    }

    public function test_secureDefault_honors_an_overridden_self_writable_attribute_set(): void
    {
        $acl = new RuleBasedAccessControl(AclRules::secureDefault(
            Subject::dn(self::ADMIN_DN),
            ['mail'],
        ));

        $acl->authorizeAttribute(
            $this->user(),
            new Dn(self::USER_DN),
            'mail',
            AttributeAccess::Write,
        );

        $this->addToAssertionCount(1);
    }

    public function test_secureDefault_denies_a_default_attribute_when_the_set_is_overridden(): void
    {
        $acl = new RuleBasedAccessControl(AclRules::secureDefault(
            Subject::dn(self::ADMIN_DN),
            ['mail'],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $acl->authorizeAttribute(
            $this->user(),
            new Dn(self::USER_DN),
            'displayName',
            AttributeAccess::Write,
        );
    }

    /**
     * An AttributeRule naming no attributes matches every attribute, so an empty set must grant nothing.
     */
    public function test_secureDefault_with_an_empty_self_writable_set_grants_no_self_write(): void
    {
        $acl = new RuleBasedAccessControl(AclRules::secureDefault(
            Subject::dn(self::ADMIN_DN),
            [],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $acl->authorizeAttribute(
            $this->user(),
            new Dn(self::USER_DN),
            'displayName',
            AttributeAccess::Write,
        );
    }

    public function test_secureDefault_with_an_empty_self_writable_set_still_denies_sensitive_attributes(): void
    {
        $acl = new RuleBasedAccessControl(AclRules::secureDefault(
            Subject::dn(self::ADMIN_DN),
            [],
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $acl->authorizeAttribute(
            $this->user(),
            new Dn(self::USER_DN),
            'objectClass',
            AttributeAccess::Write,
        );
    }

    public function test_secureDefault_denies_anonymous(): void
    {
        $this->expectException(OperationException::class);

        $this->subject->authorizeOperation(
            OperationType::Search,
            new AnonToken(),
            new Dn(self::OTHER_DN),
        );
    }

    public function test_secureDefault_restricts_privileged_extended_ops_to_admin(): void
    {
        $this->subject->authorizeExtendedOperation(
            $this->admin(),
            '1.3.6.1.4.1.1.1',
        );

        $this->expectException(OperationException::class);
        $this->subject->authorizeExtendedOperation(
            $this->user(),
            '1.3.6.1.4.1.1.1',
        );
    }

    public function test_secureDefault_strips_userPassword_from_another_users_read(): void
    {
        $filtered = $this->subject->filterEntry(
            $this->user(),
            $this->entry(self::OTHER_DN),
        );

        self::assertNotNull($filtered);
        self::assertNull($filtered->get('userPassword'));
        self::assertNotNull($filtered->get('cn'));
    }

    public function test_secureDefault_strips_userPassword_from_self_read(): void
    {
        $filtered = $this->subject->filterEntry(
            $this->user(),
            $this->entry(self::USER_DN),
        );

        self::assertNotNull($filtered);
        self::assertNull($filtered->get('userPassword'));
    }

    public function test_secureDefault_lets_self_write_but_not_read_its_userPassword(): void
    {
        $this->subject->authorizeAttribute(
            $this->user(),
            new Dn(self::USER_DN),
            'userPassword',
            AttributeAccess::Write,
        );

        $this->expectException(OperationException::class);
        $this->subject->authorizeAttribute(
            $this->user(),
            new Dn(self::USER_DN),
            'userPassword',
            AttributeAccess::Read,
        );
    }

    public function test_secureDefault_restricts_the_monitor_entry_to_the_administrator(): void
    {
        $this->subject->authorizeOperation(
            OperationType::Search,
            $this->admin(),
            new Dn(ServerMonitorHandler::DN),
        );

        $this->addToAssertionCount(1);
    }

    public function test_secureDefault_denies_the_monitor_entry_to_an_ordinary_identity(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->subject->authorizeOperation(
            OperationType::Search,
            $this->user(),
            new Dn(ServerMonitorHandler::DN),
        );
    }

    public function test_withMonitorAccess_can_loosen_the_default(): void
    {
        $acl = new RuleBasedAccessControl(
            AclRules::secureDefault(Subject::dn(self::ADMIN_DN))
                ->withMonitorAccess(Subject::authenticated()),
        );

        $acl->authorizeOperation(
            OperationType::Search,
            $this->user(),
            new Dn(ServerMonitorHandler::DN),
        );

        $this->addToAssertionCount(1);
    }

    public function test_withMonitorAccess_given_no_subject_denies_everyone(): void
    {
        $acl = new RuleBasedAccessControl(
            AclRules::secureDefault(Subject::dn(self::ADMIN_DN))
                ->withMonitorAccess(null),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $acl->authorizeOperation(
            OperationType::Search,
            $this->admin(),
            new Dn(ServerMonitorHandler::DN),
        );
    }

    public function test_withSubschemaAccess_can_tighten_to_the_administrator(): void
    {
        $acl = new RuleBasedAccessControl(
            AclRules::secureDefault(Subject::dn(self::ADMIN_DN))
                ->withSubschemaAccess(
                    Subject::dn(self::ADMIN_DN),
                    new Dn('cn=Subschema'),
                ),
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $acl->authorizeOperation(
            OperationType::Search,
            $this->user(),
            new Dn('cn=Subschema'),
        );
    }

    public function test_withSubschemaAccess_can_loosen_to_anyone(): void
    {
        $acl = new RuleBasedAccessControl(
            AclRules::secureDefault(Subject::dn(self::ADMIN_DN))
                ->withSubschemaAccess(
                    Subject::anyone(),
                    new Dn('cn=Subschema'),
                ),
        );

        $acl->authorizeOperation(
            OperationType::Search,
            new AnonToken(),
            new Dn('cn=Subschema'),
        );

        $this->addToAssertionCount(1);
    }

    public function test_replaceAttributeRules_discards_the_credential_protection(): void
    {
        $rules = AclRules::secureDefault(Subject::dn(self::ADMIN_DN))
            ->replaceAttributeRules(AttributeRule::allow(
                Subject::authenticated(),
                Target::any(),
                'description',
            )->forWrite());

        self::assertSame(
            ['description'],
            array_merge(...array_map(
                static fn(AttributeRule $rule): array => $rule->attributes,
                $rules->attributes,
            )),
        );
    }

    public function test_appendAttributeRules_keeps_the_credential_protection(): void
    {
        $rules = AclRules::secureDefault(Subject::dn(self::ADMIN_DN))
            ->appendAttributeRules(AttributeRule::allow(
                Subject::authenticated(),
                Target::any(),
                'description',
            )->forWrite());

        // userPassword must still be unreadable to everyone once another rule has been added.
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        (new RuleBasedAccessControl($rules))->authorizeAttribute(
            $this->admin(),
            new Dn(self::USER_DN),
            'userPassword',
            AttributeAccess::Read,
        );
    }

    public function test_appendControlRules_leaves_existing_rules_matching_first(): void
    {
        $rules = AclRules::fromEmpty()
            ->appendControlRules(ControlRule::deny(
                Subject::anyone(),
                Target::any(),
                Control::OID_PROXY_AUTHORIZATION,
            ))
            ->appendControlRules(ControlRule::allow(
                Subject::anyone(),
                Target::any(),
                Control::OID_PROXY_AUTHORIZATION,
            ));

        self::assertFalse((new RuleBasedAccessControl($rules))->mayUseControl(
            $this->user(),
            Control::OID_PROXY_AUTHORIZATION,
        ));
    }

    public function test_prependControlRules_matches_ahead_of_existing_rules(): void
    {
        $rules = AclRules::fromEmpty()
            ->appendControlRules(ControlRule::allow(
                Subject::anyone(),
                Target::any(),
                Control::OID_PROXY_AUTHORIZATION,
            ))
            ->prependControlRules(ControlRule::deny(
                Subject::anyone(),
                Target::any(),
                Control::OID_PROXY_AUTHORIZATION,
            ));

        self::assertFalse((new RuleBasedAccessControl($rules))->mayUseControl(
            $this->user(),
            Control::OID_PROXY_AUTHORIZATION,
        ));
    }

    private function user(): TokenInterface
    {
        return BindToken::fromDn(self::USER_DN);
    }

    private function admin(): TokenInterface
    {
        return BindToken::fromDn(self::ADMIN_DN);
    }

    private function entry(string $dn): Entry
    {
        return new Entry(
            new Dn($dn),
            new Attribute('cn', 'x'),
            new Attribute('userPassword', '{SHA}secret'),
        );
    }
}
