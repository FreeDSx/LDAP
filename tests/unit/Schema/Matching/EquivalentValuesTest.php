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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Matching;

use FreeDSx\Ldap\Schema\Matching\Comparator\CaseExactComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\GeneralizedTimeComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\IntegerComparator;
use FreeDSx\Ldap\Schema\Matching\Comparator\NameAndOptionalUidComparator;
use FreeDSx\Ldap\Schema\Matching\EquivalentValues;
use PHPUnit\Framework\TestCase;

final class EquivalentValuesTest extends TestCase
{
    public function test_it_finds_a_duplicate_the_rule_folds_together(): void
    {
        self::assertSame(
            'same',
            EquivalentValues::firstDuplicate(
                new CaseIgnoreComparator(),
                ['SAME', 'other', 'same'],
            ),
        );
    }

    public function test_it_keeps_values_a_case_exact_rule_treats_as_distinct(): void
    {
        self::assertNull(EquivalentValues::firstDuplicate(
            new CaseExactComparator(),
            ['https://Example.test', 'https://example.test'],
        ));
    }

    public function test_it_keeps_values_whose_index_keys_collide_on_the_separator(): void
    {
        $comparator = new NameAndOptionalUidComparator();
        $withUid = "cn=a,dc=x#'0101'B";
        $withoutUid = 'cn=a,dc=x#0101';

        self::assertSame(
            $comparator->indexKey($withUid),
            $comparator->indexKey($withoutUid),
        );
        self::assertNull(EquivalentValues::firstDuplicate(
            $comparator,
            [$withUid, $withoutUid],
        ));
    }

    public function test_it_keeps_two_values_the_rule_cannot_key(): void
    {
        self::assertNull(EquivalentValues::firstDuplicate(
            new GeneralizedTimeComparator(),
            ['not a time', 'also not a time'],
        ));
    }

    public function test_it_finds_a_duplicate_under_a_rule_that_cannot_be_keyed(): void
    {
        self::assertSame(
            '01',
            EquivalentValues::firstDuplicate(
                new IntegerComparator(),
                ['1', '01'],
            ),
        );
    }

    public function test_it_reports_the_positions_the_matching_values_arrived_at(): void
    {
        $held = EquivalentValues::of(
            new CaseIgnoreComparator(),
            ['alpha', 'beta', 'ALPHA'],
        );

        self::assertSame(
            [0 => 'alpha', 2 => 'ALPHA'],
            $held->matching('Alpha'),
        );
    }

    public function test_it_reports_nothing_matching_a_value_it_does_not_hold(): void
    {
        $held = EquivalentValues::of(
            new CaseIgnoreComparator(),
            ['alpha'],
        );

        self::assertSame(
            [],
            $held->matching('beta'),
        );
        self::assertFalse($held->containsEquivalentOf('beta'));
    }
}
