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

namespace Tests\Unit\FreeDSx\Ldap\Schema\Matching\Comparator;

use FreeDSx\Ldap\Schema\Matching\Comparator\GeneralizedTimeComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class GeneralizedTimeComparatorTest extends TestCase
{
    private GeneralizedTimeComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new GeneralizedTimeComparator();
    }

    public function test_equals_same_utc_timestamp(): void
    {
        $result = $this->subject->equals(
            '20060102150405Z',
            '20060102150405Z',
        );

        self::assertTrue($result);
    }

    public function test_equals_utc_z_and_offset_zero(): void
    {
        $result = $this->subject->equals(
            '20060102150405Z',
            '20060102150405+0000',
        );

        self::assertTrue($result);
    }

    public function test_equals_different_times(): void
    {
        $result = $this->subject->equals(
            '20060102150405Z',
            '20060102160405Z',
        );

        self::assertFalse($result);
    }

    public function test_equals_invalid_value_returns_false(): void
    {
        $result = $this->subject->equals(
            'not-a-time',
            '20060102150405Z',
        );

        self::assertFalse($result);
    }

    public function test_compare_earlier_time_is_less(): void
    {
        $result = $this->subject->compare(
            '20060102140405Z',
            '20060102150405Z',
        );

        self::assertLessThan(0, $result);
    }

    public function test_compare_later_time_is_greater(): void
    {
        $result = $this->subject->compare(
            '20060102160405Z',
            '20060102150405Z',
        );

        self::assertGreaterThan(0, $result);
    }

    public function test_compare_equal(): void
    {
        $result = $this->subject->compare(
            '20060102150405Z',
            '20060102150405Z',
        );

        self::assertSame(0, $result);
    }

    public function test_substring_always_returns_false(): void
    {
        $result = $this->subject->substringMatches(
            '20060102150405Z',
            new SubstringAssertion(initial: '2006'),
        );

        self::assertFalse($result);
    }

    public function test_index_key_is_shared_by_spellings_of_one_instant(): void
    {
        self::assertSame(
            $this->subject->indexKey('20260101070000-0500'),
            $this->subject->indexKey('20260101120000Z'),
        );
    }

    public function test_a_bare_spelling_names_no_instant(): void
    {
        // RFC 4517 3.3.13 makes the zone mandatory, and the syntax validator refuses the value on the way in.
        self::assertNull($this->subject->indexKey('20260101120000'));
        self::assertFalse($this->subject->equals('20260101120000', '20260101120000'));
    }

    public function test_a_fractional_value_equals_itself(): void
    {
        self::assertTrue($this->subject->equals(
            '20260101120000.500000Z',
            '20260101120000.5Z',
        ));
        self::assertNotNull($this->subject->indexKey('20260101120000.500000Z'));
    }

    public function test_values_a_fraction_apart_stay_distinct(): void
    {
        self::assertFalse($this->subject->equals(
            '20260101120000.100000Z',
            '20260101120000.200000Z',
        ));
        self::assertNotSame(
            $this->subject->indexKey('20260101120000.100000Z'),
            $this->subject->indexKey('20260101120000.200000Z'),
        );
    }

    public function test_index_keys_carrying_a_fraction_still_sort_chronologically(): void
    {
        $keys = [
            (string) $this->subject->indexKey('20260101120000.200000Z'),
            (string) $this->subject->indexKey('20260101120000Z'),
            (string) $this->subject->indexKey('20260101120000.100000Z'),
        ];
        sort($keys);

        self::assertSame(
            [
                (string) $this->subject->indexKey('20260101120000Z'),
                (string) $this->subject->indexKey('20260101120000.100000Z'),
                (string) $this->subject->indexKey('20260101120000.200000Z'),
            ],
            $keys,
        );
    }

    public function test_an_unparseable_value_sorts_after_every_real_instant(): void
    {
        self::assertSame(
            1,
            $this->subject->compare('not-a-time', '19700101000000Z'),
        );
        self::assertSame(
            -1,
            $this->subject->compare('19700101000000Z', 'not-a-time'),
        );
        self::assertSame(
            0,
            $this->subject->compare('not-a-time', 'also-not-a-time'),
        );
    }

    public function test_index_key_differs_for_different_instants(): void
    {
        self::assertNotSame(
            $this->subject->indexKey('20260101120000Z'),
            $this->subject->indexKey('20260101120001Z'),
        );
    }

    /**
     * A lexical comparison over the key has to agree with the rule's own ordering.
     */
    public function test_index_keys_sort_in_chronological_order(): void
    {
        self::assertLessThan(
            0,
            strcmp(
                (string) $this->subject->indexKey('20260101070000-0500'),
                (string) $this->subject->indexKey('20260101120001Z'),
            ),
        );
    }

    public function test_index_key_is_null_for_an_unparseable_value(): void
    {
        self::assertNull($this->subject->indexKey('not-a-time'));
    }

    public function test_index_fragment_is_null_because_the_rule_has_no_substring_form(): void
    {
        self::assertNull($this->subject->indexFragment('2026'));
    }
}
