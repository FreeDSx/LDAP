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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;

trait IntegerRangeTestsTrait
{
    private const WIDE_INTEGERS_DN = 'ou=wide-integers,dc=foo,dc=bar';

    private const WIDE_INTEGERS = [
        '-99999999999999999999',
        '-9223372036854775809',
        '-9223372036854775808',
        '5',
        '9223372036854775807',
        '9223372036854775808',
        '99999999999999999999',
    ];

    #[DataProvider('wideIntegerFilterProvider')]
    public function testAnIntegerFilterComparesPastTheSigned64BitLimits(
        FilterInterface $filter,
        string ...$expected,
    ): void {
        $this->seedWideIntegers();

        self::assertEqualsCanonicalizing(
            $expected,
            $this->wideIntegersMatching($filter),
        );
    }

    public function testASortOrdersIntegersPastTheSigned64BitLimits(): void
    {
        $this->skipUnlessSortingPastTheSigned64BitLimits();
        $this->seedWideIntegers();

        self::assertSame(
            self::WIDE_INTEGERS,
            $this->wideIntegersMatching(
                Filters::present('gidNumber'),
                new SortingControl(SortKey::ascending('gidNumber')),
            ),
        );
    }

    public function testAReverseSortOrdersIntegersPastTheSigned64BitLimits(): void
    {
        $this->skipUnlessSortingPastTheSigned64BitLimits();
        $this->seedWideIntegers();

        self::assertSame(
            array_reverse(self::WIDE_INTEGERS),
            $this->wideIntegersMatching(
                Filters::present('gidNumber'),
                new SortingControl(SortKey::descending('gidNumber')),
            ),
        );
    }

    /**
     * @return Generator<string, list<FilterInterface|string>>
     */
    public static function wideIntegerFilterProvider(): Generator
    {
        yield 'at least one past the maximum' => [
            Filters::gte(
                'gidNumber',
                '9223372036854775808',
            ),
            '9223372036854775808',
            '99999999999999999999',
        ];
        yield 'at least a value no 64-bit integer reaches' => [
            Filters::gte(
                'gidNumber',
                '99999999999999999999',
            ),
            '99999999999999999999',
        ];
        yield 'at most one below the minimum' => [
            Filters::lte(
                'gidNumber',
                '-9223372036854775809',
            ),
            '-99999999999999999999',
            '-9223372036854775809',
        ];
        yield 'at most a value no 64-bit integer reaches' => [
            Filters::lte(
                'gidNumber',
                '-99999999999999999999',
            ),
            '-99999999999999999999',
        ];
        yield 'at least a value inside the limits' => [
            Filters::gte(
                'gidNumber',
                '5',
            ),
            '5',
            '9223372036854775807',
            '9223372036854775808',
            '99999999999999999999',
        ];
    }

    private function skipUnlessSortingPastTheSigned64BitLimits(): void
    {
        if (!static::sortsPastTheSigned64BitLimits()) {
            self::markTestSkipped('This backend sorts integers past the signed 64-bit limits as equal.');
        }
    }

    /**
     * One group per wide integer, seeded once since the server is shared across the class.
     */
    private function seedWideIntegers(): void
    {
        $this->asAdmin(function (LdapClient $admin): void {
            if ($admin->read(self::WIDE_INTEGERS_DN) !== null) {
                return;
            }

            $admin->create(Entry::fromArray(
                self::WIDE_INTEGERS_DN,
                [
                    'objectClass' => 'organizationalUnit',
                    'ou' => 'wide-integers',
                ],
            ));

            foreach (self::WIDE_INTEGERS as $index => $gidNumber) {
                $admin->create(Entry::fromArray(
                    "cn=wide-{$index}," . self::WIDE_INTEGERS_DN,
                    [
                        'objectClass' => 'posixGroup',
                        'cn' => "wide-{$index}",
                        'gidNumber' => $gidNumber,
                    ],
                ));
            }
        });
    }

    /**
     * The gidNumber of each wide integer group the filter matches, in the order returned.
     *
     * @return list<string>
     */
    private function wideIntegersMatching(
        FilterInterface $filter,
        Control ...$controls,
    ): array {
        $values = [];
        $entries = $this->ldapClient()->search(
            Operations::search(
                $filter,
                'gidNumber',
            )
                ->base(self::WIDE_INTEGERS_DN)
                ->useSubtreeScope(),
            ...$controls,
        );

        foreach ($entries as $entry) {
            $values[] = $entry->get('gidNumber')?->firstValue() ?? '';
        }

        return $values;
    }
}
