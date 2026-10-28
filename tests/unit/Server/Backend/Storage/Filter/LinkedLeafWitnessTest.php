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

    public function test_an_extensible_match_by_another_rule_is_not_handed_the_value_it_asserts(): void
    {
        self::assertNotContains(
            self::GROUP_C,
            $this->subject->witness(
                $this->person(),
                Filters::extensible(
                    'memberOf',
                    self::GROUP_C,
                    'caseIgnoreMatch',
                ),
            )->get('memberOf')?->getValues() ?? [],
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

    private function person(): Entry
    {
        return new Entry(
            new Dn(self::ALICE),
            new Attribute(
                'cn',
                'alice',
            ),
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
