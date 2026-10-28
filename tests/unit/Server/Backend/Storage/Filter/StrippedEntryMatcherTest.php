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
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\MatchingRuleFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\StrippedEntryMatcher;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\ServerOptions;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;

final class StrippedEntryMatcherTest extends TestCase
{
    use ServerContainerTrait;

    private const BOB = 'cn=bob,dc=foo,dc=bar';

    private const STAFF = 'cn=staff,dc=foo,dc=bar';

    private FilterEvaluatorInterface&MockObject $mockEvaluator;

    private StrippedEntryMatcher $subject;

    protected function setUp(): void
    {
        $this->mockEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->subject = new StrippedEntryMatcher(
            $this->mockEvaluator,
            $this->fromContainer(ServerOptions::class)->getSchema(),
            $this->fromContainer(LinkedAttributes::class),
            $this->fromContainer(LinkedLeafWitness::class),
        );
        $this->fromContainer(InMemoryStorage::class)->store(EntryFixture::withUuid(new Entry(
            new Dn(self::STAFF),
            new Attribute(
                'member',
                self::BOB,
            ),
        )));
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

    public function test_withholding_anything_concerns_an_extensible_match_naming_no_attribute(): void
    {
        self::assertTrue($this->subject->concerns(
            new MatchingRuleFilter(
                'caseIgnoreMatch',
                null,
                'alice',
            ),
            'sn',
        ));
    }

    #[DataProvider('linkedOrDerivedFilterProvider')]
    public function test_withholding_a_type_does_not_concern_a_linked_or_derived_filter_that_does_not_read_it(
        FilterInterface $filter,
    ): void {
        self::assertFalse($this->subject->concerns(
            $filter,
            'userpassword',
        ));
    }

    public function test_withholding_the_linked_type_a_filter_names_concerns_it(): void
    {
        self::assertTrue($this->subject->concerns(
            Filters::equal(
                'memberOf',
                self::STAFF,
            ),
            'memberof',
        ));
    }

    public function test_the_linked_types_of_a_filter_are_those_held_apart_from_the_entry(): void
    {
        self::assertSame(
            [
                'memberof',
                'member',
            ],
            $this->subject->linkedTypes(Filters::and(
                Filters::equal(
                    'memberOf',
                    self::STAFF,
                ),
                Filters::equal(
                    'cn',
                    'bob',
                ),
                Filters::present('member'),
            )),
        );
    }

    public function test_a_linked_value_the_entry_does_not_carry_still_counts_once_stripped(): void
    {
        $judged = $this->judgedOnceStripped(
            ['description' => true],
            Filters::and(
                Filters::equal(
                    'member',
                    self::BOB,
                ),
                Filters::not(Filters::equal(
                    'description',
                    'retired',
                )),
            ),
        );

        self::assertSame(
            [self::BOB],
            $judged->get('member')?->getValues(),
        );
        self::assertFalse($judged->has('description'));
    }

    public function test_a_withheld_linked_type_is_not_counted_from_what_storage_holds(): void
    {
        $judged = $this->judgedOnceStripped(
            ['member' => true],
            Filters::equal(
                'member',
                self::BOB,
            ),
        );

        self::assertFalse($judged->has('member'));
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
            ['userpassword' => true],
            $filter,
        ));
        self::assertInstanceOf(
            Entry::class,
            $judged,
        );
        self::assertTrue($judged->has('cn'));
        self::assertFalse($judged->has('userPassword'));
    }

    public static function linkedOrDerivedFilterProvider(): Generator
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
                self::BOB,
            ),
        ];
        yield 'back-link' => [
            Filters::equal(
                'memberOf',
                self::STAFF,
            ),
        ];
    }

    /**
     * @param array<string, true> $withheld
     */
    private function judgedOnceStripped(
        array $withheld,
        FilterInterface $filter,
    ): Entry {
        $judged = null;
        $this->mockEvaluator
            ->expects(self::once())
            ->method('evaluate')
            ->willReturnCallback(static function (Entry $entry) use (&$judged): bool {
                $judged = $entry;

                return true;
            });

        $this->subject->stillMatches(
            new Entry(
                new Dn(self::STAFF),
                new Attribute(
                    'cn',
                    'staff',
                ),
                new Attribute(
                    'description',
                    'retired',
                ),
            ),
            $withheld,
            $filter,
        );
        self::assertInstanceOf(
            Entry::class,
            $judged,
        );

        return $judged;
    }
}
