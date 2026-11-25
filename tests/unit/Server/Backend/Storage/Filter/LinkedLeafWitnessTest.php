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
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\ServerOptions;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;

final class LinkedLeafWitnessTest extends TestCase
{
    use ServerContainerTrait;

    private const ALICE = 'cn=alice,dc=example,dc=com';

    private const BOB = 'cn=bob,dc=example,dc=com';

    private const GROUP_A = 'cn=group-a,dc=example,dc=com';

    private const GROUP_C = 'cn=group-c,dc=example,dc=com';

    private LinkedLeafWitness $subject;

    protected function setUp(): void
    {
        $storage = $this->fromContainer(InMemoryStorage::class);
        $this->subject = new LinkedLeafWitness(
            $storage,
            $this->fromContainer(LinkedAttributes::class),
            $this->fromContainer(ServerOptions::class)->getSchema(),
        );

        foreach (EntryFixture::allWithUuid(
            $this->group(
                'a',
                self::ALICE,
            ),
            $this->group(
                'b',
                self::BOB,
            ),
            $this->group(
                'c',
                self::ALICE,
            ),
        ) as $group) {
            $storage->store($group);
        }
    }

    public function test_one_filter_witnesses_each_entry_with_only_the_values_that_entry_holds(): void
    {
        $filter = Filters::or(
            Filters::equal(
                'member',
                self::ALICE,
            ),
            Filters::equal(
                'member',
                self::BOB,
            ),
        );

        for ($pass = 0; $pass < 2; $pass++) {
            self::assertSame(
                [self::ALICE],
                $this->subject->witness(
                    $this->group('a'),
                    $filter,
                )->get('member')?->getValues(),
            );
            self::assertSame(
                [self::BOB],
                $this->subject->witness(
                    $this->group('b'),
                    $filter,
                )->get('member')?->getValues(),
            );
        }
    }

    public function test_a_filter_naming_no_linked_attribute_leaves_the_entry_untouched(): void
    {
        $entry = $this->group('a');

        self::assertSame(
            $entry,
            $this->subject->witness(
                $entry,
                Filters::equal(
                    'cn',
                    'group-a',
                ),
            ),
        );
    }

    #[DataProvider('equalityRuleProvider')]
    public function test_an_extensible_match_by_equality_witnesses_the_value_it_asserts(?string $rule): void
    {
        self::assertSame(
            [self::GROUP_C],
            $this->subject->witness(
                $this->person(),
                Filters::extensible(
                    'memberOf',
                    self::GROUP_C,
                    $rule,
                ),
            )->get('memberOf')?->getValues(),
        );
    }

    #[DataProvider('everyValueFilterProvider')]
    public function test_a_leaf_any_value_may_answer_is_handed_every_value_the_entry_holds(FilterInterface $filter): void
    {
        self::assertSame(
            [self::GROUP_A, self::GROUP_C],
            $this->subject->witness(
                $this->person(),
                $filter,
            )->get('memberOf')?->getValues(),
        );
    }

    public function test_an_extensible_match_by_an_unrecognized_rule_is_not_handed_every_value(): void
    {
        self::assertSame(
            [self::GROUP_A],
            $this->subject->witness(
                $this->person(),
                Filters::extensible(
                    'memberOf',
                    self::GROUP_C,
                    '1.2.3.4.5',
                ),
            )->get('memberOf')?->getValues(),
        );
    }

    public function test_an_entry_showing_the_attribute_whole_is_not_handed_more_values(): void
    {
        self::assertSame(
            [self::GROUP_C],
            $this->subject->witness(
                $this->person(new Attribute(
                    'memberOf',
                    self::GROUP_C,
                )),
                Filters::greaterThanOrEqual(
                    'memberOf',
                    self::GROUP_C,
                ),
            )->get('memberOf')?->getValues(),
        );
    }

    public function test_an_entry_showing_a_range_of_the_attribute_is_handed_every_value(): void
    {
        self::assertSame(
            [self::GROUP_A, self::GROUP_C],
            $this->subject->witness(
                $this->person(new Attribute(
                    'memberOf;range=0-0',
                    self::GROUP_A,
                )),
                Filters::greaterThanOrEqual(
                    'memberOf',
                    self::GROUP_C,
                ),
            )->get(
                'memberOf',
                true,
            )?->getValues(),
        );
    }

    /**
     * @return Generator<string, array{?string}>
     */
    public static function equalityRuleProvider(): Generator
    {
        yield 'no rule' => [null];
        yield 'the equality rule by name' => ['distinguishedNameMatch'];
        yield 'the equality rule by OID' => ['2.5.13.1'];
    }

    /**
     * @return Generator<string, array{FilterInterface}>
     */
    public static function everyValueFilterProvider(): Generator
    {
        yield 'an extensible match by another rule' => [Filters::extensible(
            'memberOf',
            self::GROUP_C,
            'caseIgnoreMatch',
        )];
        yield 'an extensible match by another rule by OID' => [Filters::extensible(
            'memberOf',
            self::GROUP_C,
            '2.5.13.2',
        )];
        yield 'a greater-or-equal' => [Filters::greaterThanOrEqual(
            'memberOf',
            self::GROUP_C,
        )];
        yield 'a less-or-equal' => [Filters::lessThanOrEqual(
            'memberOf',
            self::GROUP_A,
        )];
        yield 'a negated extensible match by another rule' => [Filters::not(Filters::extensible(
            'memberOf',
            self::GROUP_C,
            'caseIgnoreMatch',
        ))];
        yield 'one beside an equality on the same attribute' => [Filters::and(
            Filters::equal(
                'memberOf',
                self::GROUP_C,
            ),
            Filters::extensible(
                'memberOf',
                self::GROUP_C,
                'caseIgnoreMatch',
            ),
        )];
    }

    private function person(Attribute ...$attributes): Entry
    {
        return new Entry(
            new Dn(self::ALICE),
            new Attribute(
                'cn',
                'alice',
            ),
            ...$attributes,
        );
    }

    private function group(
        string $name,
        string ...$members,
    ): Entry {
        $group = new Entry(
            new Dn("cn=group-{$name},dc=example,dc=com"),
            new Attribute(
                'cn',
                "group-{$name}",
            ),
        );

        if ($members !== []) {
            $group->set(
                'member',
                ...$members,
            );
        }

        return $group;
    }
}
