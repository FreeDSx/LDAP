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

use FreeDSx\Ldap\Schema\Matching\Comparator\TelephoneNumberComparator;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use PHPUnit\Framework\TestCase;

final class TelephoneNumberComparatorTest extends TestCase
{
    private TelephoneNumberComparator $subject;

    protected function setUp(): void
    {
        $this->subject = new TelephoneNumberComparator();
    }

    public function test_equals_strips_spaces_and_hyphens(): void
    {
        $result = $this->subject->equals(
            '+1 800 555-1234',
            '+18005551234',
        );

        self::assertTrue($result);
    }

    public function test_equals_case_insensitive(): void
    {
        $result = $this->subject->equals('1-800-FOO', '1800foo');

        self::assertTrue($result);
    }

    public function test_equals_different_numbers(): void
    {
        $result = $this->subject->equals(
            '+1 800 555-1234',
            '+1 800 555-9999',
        );

        self::assertFalse($result);
    }

    public function test_compare_equal_after_normalization(): void
    {
        $result = $this->subject->compare(
            '+1 800 555-1234',
            '+18005551234',
        );

        self::assertSame(0, $result);
    }

    public function test_substring_strips_formatting_before_matching(): void
    {
        $result = $this->subject->substringMatches(
            '1 800 555-1234',
            new SubstringAssertion(initial: '1800'),
        );

        self::assertTrue($result);
    }
}
