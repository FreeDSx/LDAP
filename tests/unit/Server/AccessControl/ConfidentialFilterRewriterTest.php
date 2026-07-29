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

use FreeDSx\Ldap\Schema\StandardSchemaProvider;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\ConfidentialAttributePolicy;
use FreeDSx\Ldap\Server\AccessControl\ConfidentialFilterRewriter;
use FreeDSx\Ldap\Server\AccessControl\Rule\ConfidentialAccessRule;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;

final class ConfidentialFilterRewriterTest extends TestCase
{
    private ConfidentialFilterRewriter $subject;

    private TokenInterface $token;

    protected function setUp(): void
    {
        $this->token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $this->subject = new ConfidentialFilterRewriter(new ConfidentialAttributePolicy(
            new RuleBasedAccessControl(AclRules::fromEmpty()),
            StandardSchemaProvider::buildCore(),
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
        $subject = new ConfidentialFilterRewriter(new ConfidentialAttributePolicy(
            new RuleBasedAccessControl(AclRules::fromEmpty(
                confidential: [ConfidentialAccessRule::allowAny(Subject::authenticated())],
            )),
            StandardSchemaProvider::buildCore(),
        ));
        $filter = Filters::equal('userPassword', 'secret');

        self::assertSame(
            $filter,
            $subject->rewrite($filter, $this->token),
        );
    }

    public function test_without_a_schema_nothing_is_treated_as_confidential(): void
    {
        $subject = new ConfidentialFilterRewriter(new ConfidentialAttributePolicy(
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
}
