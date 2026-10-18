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
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use PHPUnit\Framework\TestCase;

final class LinkedLeafWitnessTest extends TestCase
{
    private const ALICE = 'cn=alice,dc=example,dc=com';

    private const BOB = 'cn=bob,dc=example,dc=com';

    private LinkedLeafWitness $subject;

    protected function setUp(): void
    {
        $this->subject = new LinkedLeafWitness(
            new class implements LinkedValueLookupInterface {
                private const HELD = [
                    'cn=group-a,dc=example,dc=com' => ['cn=alice,dc=example,dc=com'],
                    'cn=group-b,dc=example,dc=com' => ['cn=bob,dc=example,dc=com'],
                ];

                public function heldLinkValues(
                    Dn $owner,
                    string $attribute,
                    array $values,
                ): array {
                    return array_values(array_intersect(
                        $values,
                        self::HELD[$owner->toString()] ?? [],
                    ));
                }

                public function anyLinkValue(
                    Dn $owner,
                    string $attribute,
                ): ?string {
                    return self::HELD[$owner->toString()][0] ?? null;
                }
            },
            new LinkedAttributes(SchemaResource::Core->load()),
        );
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

    private function group(string $name): Entry
    {
        return new Entry(
            new Dn("cn=group-{$name},dc=example,dc=com"),
            new Attribute(
                'cn',
                "group-{$name}",
            ),
        );
    }
}
