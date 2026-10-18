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

namespace Tests\Unit\FreeDSx\Ldap\Server\AccessControl\Read;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\Read\ReadVerdict;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class RuleReadScopeTest extends TestCase
{
    private BindToken $user;

    protected function setUp(): void
    {
        $this->user = BindToken::fromDn('cn=user,dc=foo,dc=bar');
    }

    public function test_a_name_no_rule_reads_is_allowed_everywhere(): void
    {
        $scope = $this->policy()->readScope($this->user);

        self::assertSame(
            ReadVerdict::Allow,
            $scope->verdict('cn'),
        );
    }

    public function test_a_rule_for_anyone_anywhere_decides_the_name_everywhere(): void
    {
        $scope = $this->policy(AttributeRule::deny(
            Subject::anyone(),
            Target::any(),
            'userPassword',
        )->forRead())->readScope($this->user);

        self::assertSame(
            ReadVerdict::Deny,
            $scope->verdict('userpassword'),
        );
        self::assertSame(
            ReadVerdict::Allow,
            $scope->verdict('cn'),
        );
    }

    public function test_a_rule_whose_subject_the_token_is_not_is_passed_over(): void
    {
        $policy = $this->policy(AttributeRule::deny(
            Subject::anonymous(),
            Target::any(),
            'mail',
        )->forRead());

        self::assertSame(
            ReadVerdict::Allow,
            $policy->readScope($this->user)->verdict('mail'),
        );
        self::assertSame(
            ReadVerdict::Deny,
            $policy->readScope(new AnonToken())->verdict('mail'),
        );
    }

    public function test_an_allow_ahead_of_a_deny_decides_for_the_identity_it_names(): void
    {
        $policy = $this->policy(
            AttributeRule::allow(
                Subject::dn('cn=user,dc=foo,dc=bar'),
                Target::any(),
                'mail',
            )->forRead(),
            AttributeRule::deny(
                Subject::anyone(),
                Target::any(),
                'mail',
            )->forRead(),
        );

        self::assertSame(
            ReadVerdict::Allow,
            $policy->readScope($this->user)->verdict('mail'),
        );
        self::assertSame(
            ReadVerdict::Deny,
            $policy->readScope(BindToken::fromDn('cn=other,dc=foo,dc=bar'))->verdict('mail'),
        );
    }

    public function test_a_write_rule_does_not_decide_a_read(): void
    {
        $scope = $this->policy(AttributeRule::deny(
            Subject::anyone(),
            Target::any(),
            'cn',
        )->forWrite())->readScope($this->user);

        self::assertSame(
            ReadVerdict::Allow,
            $scope->verdict('cn'),
        );
    }

    public function test_a_dn_subtree_subject_is_decided_from_the_identity_alone(): void
    {
        $policy = $this->policy(AttributeRule::deny(
            Subject::dnSubtree('ou=hidden,dc=foo,dc=bar'),
            Target::any(),
            'mail',
        )->forRead());

        self::assertSame(
            ReadVerdict::Deny,
            $policy->readScope(BindToken::fromDn('cn=a,ou=hidden,dc=foo,dc=bar'))->verdict('mail'),
        );
        self::assertSame(
            ReadVerdict::Allow,
            $policy->readScope($this->user)->verdict('mail'),
        );
    }

    public function test_a_rule_naming_no_attribute_decides_every_name(): void
    {
        $scope = $this->policy(AttributeRule::deny(
            Subject::anyone(),
            Target::any(),
        )->forRead())->readScope($this->user);

        self::assertSame(
            ReadVerdict::Deny,
            $scope->verdict('cn'),
        );
        self::assertSame(
            ReadVerdict::Deny,
            $scope->verdict('anythingelse'),
        );
    }

    public function test_a_subtree_scoped_rule_leaves_the_decision_to_each_entry(): void
    {
        $scope = $this->policy(AttributeRule::deny(
            Subject::anyone(),
            Target::subtree('ou=hidden,dc=foo,dc=bar'),
            'mail',
        )->forRead())->readScope($this->user);

        self::assertSame(
            ReadVerdict::PerEntry,
            $scope->verdict('mail'),
        );
        self::assertFalse($scope->isReadableOn(
            'mail',
            new Dn('cn=a,ou=hidden,dc=foo,dc=bar'),
        ));
        self::assertTrue($scope->isReadableOn(
            'mail',
            new Dn('cn=a,ou=shown,dc=foo,dc=bar'),
        ));
    }

    public function test_a_self_rule_leaves_the_decision_to_each_entry(): void
    {
        $scope = $this->policy(
            AttributeRule::allow(
                Subject::self(),
                Target::any(),
                'mail',
            )->forRead(),
            AttributeRule::deny(
                Subject::anyone(),
                Target::any(),
                'mail',
            )->forRead(),
        )->readScope($this->user);

        self::assertSame(
            ReadVerdict::PerEntry,
            $scope->verdict('mail'),
        );
        self::assertTrue($scope->isReadableOn(
            'mail',
            new Dn('cn=user,dc=foo,dc=bar'),
        ));
        self::assertFalse($scope->isReadableOn(
            'mail',
            new Dn('cn=other,dc=foo,dc=bar'),
        ));
    }

    public function test_a_group_rule_leaves_the_decision_to_each_entry(): void
    {
        $scope = $this->policy(AttributeRule::deny(
            Subject::group('cn=staff,dc=foo,dc=bar'),
            Target::any(),
            'mail',
        )->forRead())->readScope($this->user);

        self::assertSame(
            ReadVerdict::PerEntry,
            $scope->verdict('mail'),
        );
    }

    public function test_a_subject_that_cannot_be_decided_on_a_deny_withholds_the_attribute(): void
    {
        $scope = $this->policy(AttributeRule::deny(
            Subject::callback(static fn(): bool => throw new RuntimeException('undecidable')),
            Target::any(),
            'mail',
        )->forRead())->readScope($this->user);

        self::assertFalse($scope->isReadableOn(
            'mail',
            new Dn('cn=a,dc=foo,dc=bar'),
        ));
    }

    public function test_readable_keeps_the_same_entry_when_nothing_is_withheld(): void
    {
        $entry = new Entry(
            new Dn('cn=a,dc=foo,dc=bar'),
            new Attribute(
                'cn',
                'a',
            ),
        );

        self::assertSame(
            $entry,
            $this->policy()->readScope($this->user)->readable($entry),
        );
    }

    public function test_readable_withholds_every_form_of_a_denied_type(): void
    {
        $readable = $this->policy(AttributeRule::deny(
            Subject::anyone(),
            Target::any(),
            'userPassword',
        )->forRead())->readScope($this->user)->readable(new Entry(
            new Dn('cn=a,dc=foo,dc=bar'),
            new Attribute(
                'cn',
                'a',
            ),
            new Attribute(
                'userPassword',
                'secret',
            ),
            new Attribute(
                'USERPASSWORD;binary',
                'secret',
            ),
        ));

        self::assertSame(
            ['cn'],
            array_map(
                static fn(Attribute $attribute): string => $attribute->getDescription(),
                $readable->getAttributes(),
            ),
        );
    }

    public function test_an_entry_is_visible_by_the_search_rules(): void
    {
        $scope = (new RuleBasedAccessControl(AclRules::fromEmpty(
            operations: [OperationRule::allow(
                Subject::anyone(),
                Target::subtree('ou=shown,dc=foo,dc=bar'),
            )],
        )))->readScope($this->user);

        self::assertTrue($scope->isEntryVisible(new Entry(new Dn('cn=a,ou=shown,dc=foo,dc=bar'))));
        self::assertFalse($scope->isEntryVisible(new Entry(new Dn('cn=a,ou=hidden,dc=foo,dc=bar'))));
    }

    private function policy(AttributeRule ...$rules): RuleBasedAccessControl
    {
        return new RuleBasedAccessControl(AclRules::fromEmpty(
            operations: [OperationRule::allow(Subject::anyone())],
            attributes: $rules,
        ));
    }
}
