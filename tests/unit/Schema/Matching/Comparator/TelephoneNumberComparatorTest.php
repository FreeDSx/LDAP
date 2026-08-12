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
use PHPUnit\Framework\Attributes\DataProvider;
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

    /**
     * RFC 4518 2.6.3 names seven hyphens, not just the ASCII one.
     */
    #[DataProvider('hyphenProvider')]
    public function test_equals_strips_every_insignificant_hyphen(string $hyphen): void
    {
        self::assertTrue($this->subject->equals(
            '555' . $hyphen . '1234',
            '5551234',
        ));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function hyphenProvider(): iterable
    {
        yield 'hyphen-minus' => ["\u{002D}"];
        yield 'armenian hyphen' => ["\u{058A}"];
        yield 'hyphen' => ["\u{2010}"];
        yield 'non-breaking hyphen' => ["\u{2011}"];
        yield 'minus sign' => ["\u{2212}"];
        yield 'small hyphen-minus' => ["\u{FE63}"];
        yield 'fullwidth hyphen-minus' => ["\u{FF0D}"];
    }

    public function test_equals_folds_compatibility_digits(): void
    {
        self::assertTrue($this->subject->equals(
            "\u{FF15}\u{FF15}\u{FF15}",
            '555',
        ));
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
