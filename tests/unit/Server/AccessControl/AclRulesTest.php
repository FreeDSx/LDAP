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
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\ControlRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\Effect;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
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

    public function test_secureDefault_allows_authenticated_general_operations(): void
    {
        $this->subject->authorizeOperation(
            OperationType::Search,
            $this->user(),
            new Dn(self::OTHER_DN),
        );
        $this->subject->authorizeOperation(
            OperationType::Modify,
            $this->user(),
            new Dn(self::OTHER_DN),
        );

        $this->addToAssertionCount(1);
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
