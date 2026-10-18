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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Filter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\StrippedEntryMatcher;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class StrippedEntryMatcherTest extends TestCase
{
    private FilterEvaluatorInterface&MockObject $mockEvaluator;

    private StrippedEntryMatcher $subject;

    protected function setUp(): void
    {
        $schema = SchemaResource::Core->load();
        $this->mockEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->subject = new StrippedEntryMatcher(
            $this->mockEvaluator,
            $schema,
            new LinkedAttributes($schema),
        );
    }

    public function test_withholding_a_type_the_filter_does_not_read_does_not_concern_it(): void
    {
        self::assertFalse($this->subject->concerns(
            Filters::equal(
                'cn',
                'alice',
            ),
            'userpassword',
        ));
    }

    public function test_withholding_a_type_the_filter_reads_concerns_it(): void
    {
        self::assertTrue($this->subject->concerns(
            Filters::and(
                Filters::equal(
                    'cn',
                    'alice',
                ),
                Filters::present('userPassword'),
            ),
            'userpassword',
        ));
    }

    public function test_withholding_the_type_an_option_bearing_assertion_names_concerns_it(): void
    {
        self::assertTrue($this->subject->concerns(
            Filters::equal(
                'givenName;lang-en',
                'Ali',
            ),
            'givenname',
        ));
    }

    public function test_withholding_another_type_than_the_filter_reads_does_not_concern_it(): void
    {
        self::assertFalse($this->subject->concerns(
            Filters::equal(
                'cn',
                'alice',
            ),
            'givenname',
        ));
    }

    public function test_withholding_a_subtype_of_a_type_the_filter_names_concerns_it(): void
    {
        self::assertTrue($this->subject->concerns(
            Filters::equal(
                'name',
                'alice',
            ),
            'cn',
        ));
    }

    public function test_an_answer_is_the_same_when_asked_again(): void
    {
        $filter = Filters::equal(
            'name',
            'alice',
        );

        self::assertSame(
            $this->subject->concerns(
                $filter,
                'cn',
            ),
            $this->subject->concerns(
                $filter,
                'cn',
            ),
        );
    }

    #[DataProvider('alwaysJudgedFilterProvider')]
    public function test_withholding_anything_concerns_a_filter_whose_values_are_not_read_off_the_entry_alone(
        FilterInterface $filter,
    ): void {
        self::assertTrue($this->subject->concerns(
            $filter,
            'sn',
        ));
    }

    public function test_the_entry_is_judged_against_the_filter_without_what_was_withheld(): void
    {
        $entry = new Entry(
            new Dn('cn=alice,dc=foo,dc=bar'),
            new Attribute(
                'cn',
                'alice',
            ),
            new Attribute(
                'userPassword',
                'secret',
            ),
        );
        $filter = Filters::present('userPassword');
        $judged = null;

        $this->mockEvaluator
            ->expects(self::once())
            ->method('evaluate')
            ->willReturnCallback(static function (Entry $stripped) use (&$judged): bool {
                $judged = $stripped;

                return false;
            });

        self::assertFalse($this->subject->stillMatches(
            $entry,
            [1 => true],
            $filter,
        ));
        self::assertInstanceOf(
            Entry::class,
            $judged,
        );
        self::assertTrue($judged->has('cn'));
        self::assertFalse($judged->has('userPassword'));
    }

    public static function alwaysJudgedFilterProvider(): Generator
    {
        yield 'derived attribute' => [
            Filters::equal(
                'entryDN',
                'cn=alice,dc=foo,dc=bar',
            ),
        ];
        yield 'linked attribute' => [
            Filters::equal(
                'member',
                'cn=bob,dc=foo,dc=bar',
            ),
        ];
        yield 'extensible match naming no attribute' => [
            new MatchingRuleFilter(
                'caseIgnoreMatch',
                null,
                'alice',
            ),
        ];
    }
}
