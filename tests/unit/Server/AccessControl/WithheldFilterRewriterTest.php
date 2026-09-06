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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\WithheldAttributePolicy;
use FreeDSx\Ldap\Server\AccessControl\WithheldFilterRewriter;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\Rule\FilterAccessRule;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\AnySubjectMatcher;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;

final class WithheldFilterRewriterTest extends TestCase
{
    private WithheldFilterRewriter $subject;

    private TokenInterface $token;

    protected function setUp(): void
    {
        $this->token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $this->subject = new WithheldFilterRewriter(new WithheldAttributePolicy(
            new RuleBasedAccessControl(AclRules::fromEmpty()),
            SchemaResource::Core->load(),
        ));
    }

    public function test_an_assertion_on_a_withheld_attribute_collapses_to_absolute_false(): void
    {
        $rewritten = $this->rewrite(Filters::equal('userPassword', 'secret'));

        self::assertTrue($this->subject->isAbsoluteFalse($rewritten));
    }

    public function test_a_substring_assertion_on_a_withheld_attribute_collapses_to_absolute_false(): void
    {
        $rewritten = $this->rewrite(Filters::startsWith('userPassword', '{SHA}a'));

        self::assertTrue($this->subject->isAbsoluteFalse($rewritten));
    }

    public function test_a_presence_assertion_on_a_withheld_attribute_collapses_to_absolute_false(): void
    {
        $rewritten = $this->rewrite(Filters::present('userPassword'));

        self::assertTrue($this->subject->isAbsoluteFalse($rewritten));
    }

    public function test_a_conjunction_containing_a_withheld_assertion_collapses_to_absolute_false(): void
    {
        $rewritten = $this->rewrite(Filters::and(
            Filters::equal('cn', 'alice'),
            Filters::equal('userPassword', 'secret'),
        ));

        self::assertTrue($this->subject->isAbsoluteFalse($rewritten));
    }

    public function test_a_disjunction_drops_the_withheld_assertion_and_keeps_the_rest(): void
    {
        $rewritten = $this->rewrite(Filters::or(
            Filters::equal('cn', 'alice'),
            Filters::equal('userPassword', 'secret'),
        ));

        // The lone survivor is returned bare rather than wrapped in a one-branch disjunction.
        self::assertSame(
            '(cn=alice)',
            $rewritten->toString(),
        );
    }

    public function test_a_disjunction_keeping_more_than_one_branch_stays_a_disjunction(): void
    {
        $rewritten = $this->rewrite(Filters::or(
            Filters::equal('cn', 'alice'),
            Filters::equal('sn', 'smith'),
            Filters::equal('userPassword', 'secret'),
        ));

        self::assertSame(
            '(|(cn=alice)(sn=smith))',
            $rewritten->toString(),
        );
    }

    public function test_a_disjunction_of_only_withheld_assertions_collapses_to_absolute_false(): void
    {
        $rewritten = $this->rewrite(Filters::or(
            Filters::equal('userPassword', 'secret'),
            Filters::present('userPassword'),
        ));

        self::assertTrue($this->subject->isAbsoluteFalse($rewritten));
    }

    public function test_negating_a_withheld_assertion_matches_every_entry(): void
    {
        // Withheld reads as absent, so the negation holds for all entries rather than none.
        $rewritten = $this->rewrite(Filters::not(Filters::equal('userPassword', 'secret')));

        self::assertInstanceOf(
            AndFilter::class,
            $rewritten,
        );
        self::assertSame(
            [],
            $rewritten->get(),
        );
    }

    public function test_an_attribute_option_does_not_evade_the_rewrite(): void
    {
        $rewritten = $this->rewrite(Filters::equal('userPassword;binary', 'secret'));

        self::assertTrue($this->subject->isAbsoluteFalse($rewritten));
    }

    public function test_an_assertion_on_a_filter_denied_attribute_collapses_to_absolute_false(): void
    {
        $subject = $this->rewriterDenyingFilterOn('telephoneNumber');

        $rewritten = $subject->rewrite(
            Filters::equal('telephoneNumber', '555-0100'),
            $this->token,
        );

        self::assertTrue($subject->isAbsoluteFalse($rewritten));
    }

    /**
     * The shape a read deny alone leaves open, where a correct guess is distinguishable from a wrong one.
     */
    public function test_negating_a_filter_denied_assertion_matches_every_entry(): void
    {
        $subject = $this->rewriterDenyingFilterOn('telephoneNumber');

        $rewritten = $subject->rewrite(
            Filters::not(Filters::equal('telephoneNumber', '555-0100')),
            $this->token,
        );

        self::assertEquals(
            Filters::and(),
            $rewritten,
        );
    }

    public function test_a_filter_deny_leaves_every_other_attribute_alone(): void
    {
        $subject = $this->rewriterDenyingFilterOn('telephoneNumber');
        $filter = Filters::equal('sn', 'Bob');

        self::assertSame(
            $filter,
            $subject->rewrite($filter, $this->token),
        );
    }

    public function test_an_assertion_naming_no_attribute_is_refused_rather_than_passed_through(): void
    {
        self::expectExceptionObject(new OperationException(
            'An extensible match must name an attribute type.',
            ResultCode::INAPPROPRIATE_MATCHING,
        ));

        $this->rewrite(Filters::extensible(null, 'secret', 'caseIgnoreMatch'));
    }

    public function test_a_filter_touching_no_confidential_attribute_is_returned_unchanged(): void
    {
        $filter = Filters::and(
            Filters::equal('cn', 'alice'),
            Filters::present('objectClass'),
        );

        self::assertSame(
            $filter,
            $this->rewrite($filter),
        );
    }

    public function test_a_granted_token_keeps_the_filter_unchanged(): void
    {
        $subject = new WithheldFilterRewriter(new WithheldAttributePolicy(
            new RuleBasedAccessControl(AclRules::fromEmpty(
                confidential: [ConfidentialAccessRule::allowAny(Subject::authenticated())],
            )),
            SchemaResource::Core->load(),
        ));
        $filter = Filters::equal('userPassword', 'secret');

        self::assertSame(
            $filter,
            $subject->rewrite($filter, $this->token),
        );
    }

    public function test_without_a_schema_nothing_is_treated_as_confidential(): void
    {
        $subject = new WithheldFilterRewriter(new WithheldAttributePolicy(
            new RuleBasedAccessControl(AclRules::fromEmpty()),
        ));
        $filter = Filters::equal('userPassword', 'secret');

        self::assertSame(
            $filter,
            $subject->rewrite($filter, $this->token),
        );
    }

    private function rewrite(FilterInterface $filter): FilterInterface
    {
        return $this->subject->rewrite(
            $filter,
            $this->token,
        );
    }

    private function rewriterDenyingFilterOn(string $attribute): WithheldFilterRewriter
    {
        return new WithheldFilterRewriter(new WithheldAttributePolicy(
            new RuleBasedAccessControl(AclRules::fromEmpty(
                filters: [
                    FilterAccessRule::deny(
                        new AnySubjectMatcher(),
                        $attribute,
                    ),
                ],
            )),
            SchemaResource::Core->load(),
        ));
    }
}
