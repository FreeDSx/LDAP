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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Definition;

use FreeDSx\Ldap\Schema\Definition\MatchingRule;
use FreeDSx\Ldap\Schema\Matching\CaseIgnoreComparator;
use PHPUnit\Framework\TestCase;

final class MatchingRuleTest extends TestCase
{
    private CaseIgnoreComparator $comparator;

    protected function setUp(): void
    {
        $this->comparator = new CaseIgnoreComparator();
    }

    public function test_description_string_single_name(): void
    {
        $rule = new MatchingRule(
            oid: '2.5.13.2',
            names: ['caseIgnoreMatch'],
            syntaxOid: '1.3.6.1.4.1.1466.115.121.1.15',
            comparator: $this->comparator,
        );

        self::assertSame(
            "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            $rule->toDescriptionString(),
        );
    }

    public function test_description_string_multiple_names(): void
    {
        $rule = new MatchingRule(
            oid: '2.5.13.2',
            names: ['caseIgnoreMatch', 'caseIgnore'],
            syntaxOid: '1.3.6.1.4.1.1466.115.121.1.15',
            comparator: $this->comparator,
        );

        self::assertSame(
            "( 2.5.13.2 NAME ( 'caseIgnoreMatch' 'caseIgnore' ) SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            $rule->toDescriptionString(),
        );
    }

    public function test_description_string_with_desc(): void
    {
        $rule = new MatchingRule(
            oid: '2.5.13.2',
            names: ['caseIgnoreMatch'],
            syntaxOid: '1.3.6.1.4.1.1466.115.121.1.15',
            comparator: $this->comparator,
            desc: 'case insensitive match',
        );

        self::assertSame(
            "( 2.5.13.2 NAME 'caseIgnoreMatch' DESC 'case insensitive match' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            $rule->toDescriptionString(),
        );
    }

    public function test_description_string_with_obsolete(): void
    {
        $rule = new MatchingRule(
            oid: '2.5.13.2',
            names: ['caseIgnoreMatch'],
            syntaxOid: '1.3.6.1.4.1.1466.115.121.1.15',
            comparator: $this->comparator,
            obsolete: true,
        );

        self::assertSame(
            "( 2.5.13.2 NAME 'caseIgnoreMatch' OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
            $rule->toDescriptionString(),
        );
    }
}
