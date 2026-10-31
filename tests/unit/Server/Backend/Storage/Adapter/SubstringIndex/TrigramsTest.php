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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\Trigrams;
use PHPUnit\Framework\TestCase;

final class TrigramsTest extends TestCase
{
    public function test_it_extracts_distinct_trigrams(): void
    {
        self::assertSame(
            ['smi', 'mit', 'ith'],
            Trigrams::of('smith'),
        );
    }

    public function test_it_keeps_the_case_the_value_was_prepared_in(): void
    {
        self::assertSame(
            ['SMI', 'MIT', 'ITH'],
            Trigrams::of('SMITH'),
        );
    }

    public function test_it_returns_empty_for_values_shorter_than_three_chars(): void
    {
        self::assertSame(
            [],
            Trigrams::of('ab'),
        );
        self::assertSame(
            [],
            Trigrams::of(''),
        );
    }

    public function test_it_deduplicates_repeated_trigrams(): void
    {
        self::assertSame(
            ['aaa'],
            Trigrams::of('aaaa'),
        );
    }

    public function test_it_preserves_numeric_trigrams_as_strings(): void
    {
        self::assertSame(
            ['012', '123'],
            Trigrams::of('0123'),
        );
    }

    public function test_it_windows_multibyte_characters_by_code_point(): void
    {
        self::assertSame(
            ['naï', 'aïv', 'ïve'],
            Trigrams::of('naïve'),
        );
    }

    public function test_it_returns_empty_for_non_utf8_values(): void
    {
        self::assertSame(
            [],
            Trigrams::of("\xff\xfe\xfd\xfc"),
        );
    }
}
