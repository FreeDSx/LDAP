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

    private Attribute $cn;

    private Attribute $sn;

    private Attribute $userPassword;

    private Entry $entry;

    protected function setUp(): void
    {
        $schema = SchemaResource::Core->load();
        $this->mockEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->subject = new StrippedEntryMatcher(
            $this->mockEvaluator,
            $schema,
            new LinkedAttributes($schema),
        );

        $this->cn = new Attribute(
            'cn',
            'alice',
        );
        $this->sn = new Attribute(
            'sn',
            'smith',
        );
        $this->userPassword = new Attribute(
            'userPassword',
            'secret',
        );
        $this->entry = new Entry(
            new Dn('cn=alice,dc=foo,dc=bar'),
            $this->cn,
            $this->sn,
            $this->userPassword,
        );
    }

    public function test_an_entry_nothing_was_stripped_from_still_matches_without_being_judged(): void
    {
        $this->mockEvaluator
            ->expects(self::never())
            ->method('evaluate');

        self::assertTrue($this->subject->stillMatches(
            $this->entry,
            $this->entry,
            Filters::equal(
                'cn',
                'alice',
            ),
        ));
    }

    public function test_losing_an_attribute_the_filter_does_not_read_keeps_the_match_without_judging_it(): void
    {
        $this->mockEvaluator
            ->expects(self::never())
            ->method('evaluate');

        self::assertTrue($this->subject->stillMatches(
            $this->entry,
            $this->stripped(
                $this->cn,
                $this->sn,
            ),
            Filters::equal(
                'cn',
                'alice',
            ),
        ));
    }

    public function test_losing_an_attribute_the_filter_reads_judges_the_stripped_entry_again(): void
    {
        $stripped = $this->stripped(
            $this->cn,
            $this->sn,
        );
        $filter = Filters::and(
            Filters::equal(
                'cn',
                'alice',
            ),
            Filters::present('userPassword'),
        );

        $this->mockEvaluator
            ->expects(self::once())
            ->method('evaluate')
            ->with(
                $stripped,
                $filter,
            )
            ->willReturn(false);

        self::assertFalse($this->subject->stillMatches(
            $this->entry,
            $stripped,
            $filter,
        ));
    }

    public function test_losing_an_option_bearing_form_of_a_type_the_filter_reads_judges_the_stripped_entry_again(): void
    {
        $entry = $this->entryWithTaggedGivenName();

        $this->mockEvaluator
            ->expects(self::once())
            ->method('evaluate')
            ->willReturn(false);

        self::assertFalse($this->subject->stillMatches(
            $entry,
            Entry::raw(
                $entry->getDn(),
                [$this->cn],
            ),
            Filters::equal(
                'givenName',
                'Ali',
            ),
        ));
    }

    public function test_losing_an_option_bearing_form_of_another_type_keeps_the_match_without_judging_it(): void
    {
        $entry = $this->entryWithTaggedGivenName();

        $this->mockEvaluator
            ->expects(self::never())
            ->method('evaluate');

        self::assertTrue($this->subject->stillMatches(
            $entry,
            Entry::raw(
                $entry->getDn(),
                [$this->cn],
            ),
            Filters::equal(
                'cn',
                'alice',
            ),
        ));
    }

    public function test_losing_a_subtype_of_a_type_the_filter_names_judges_the_stripped_entry_again(): void
    {
        $this->mockEvaluator
            ->expects(self::once())
            ->method('evaluate')
            ->willReturn(false);

        self::assertFalse($this->subject->stillMatches(
            $this->entry,
            $this->stripped(
                $this->sn,
                $this->userPassword,
            ),
            Filters::equal(
                'name',
                'alice',
            ),
        ));
    }

    public function test_a_stripped_entry_rebuilt_from_other_attributes_is_judged_again(): void
    {
        $this->mockEvaluator
            ->expects(self::once())
            ->method('evaluate')
            ->willReturn(true);

        self::assertTrue($this->subject->stillMatches(
            $this->entry,
            new Entry(
                new Dn('cn=alice,dc=foo,dc=bar'),
                new Attribute(
                    'cn',
                    'alice',
                ),
                new Attribute(
                    'sn',
                    'smith',
                ),
            ),
            Filters::equal(
                'cn',
                'alice',
            ),
        ));
    }

    #[DataProvider('alwaysJudgedFilterProvider')]
    public function test_a_filter_whose_values_are_not_read_off_the_entry_alone_is_always_judged_again(
        FilterInterface $filter,
    ): void {
        $this->mockEvaluator
            ->expects(self::once())
            ->method('evaluate')
            ->willReturn(true);

        self::assertTrue($this->subject->stillMatches(
            $this->entry,
            $this->stripped(
                $this->cn,
                $this->sn,
            ),
            $filter,
        ));
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

    private function entryWithTaggedGivenName(): Entry
    {
        return new Entry(
            new Dn('cn=alice,dc=foo,dc=bar'),
            $this->cn,
            new Attribute(
                'givenName;lang-en',
                'Ali',
            ),
        );
    }

    private function stripped(Attribute ...$kept): Entry
    {
        return Entry::raw(
            $this->entry->getDn(),
            $kept,
        );
    }
}
