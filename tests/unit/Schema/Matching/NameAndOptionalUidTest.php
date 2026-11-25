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

use FreeDSx\Ldap\Schema\Matching\NameAndOptionalUid;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class NameAndOptionalUidTest extends TestCase
{
    #[DataProvider('valueProvider')]
    public function test_a_uid_is_split_off_only_after_an_unescaped_hash(
        string $value,
        string $name,
        ?string $uid,
    ): void {
        $parsed = NameAndOptionalUid::parse($value);

        self::assertSame(
            [$name, $uid],
            [$parsed->name, $parsed->uid],
        );
    }

    /**
     * @return Generator<string, array{string, string, ?string}>
     */
    public static function valueProvider(): Generator
    {
        yield 'an unescaped #' => [
            "cn=a,dc=x#'01'B",
            'cn=a,dc=x',
            "'01'B",
        ];
        yield 'an escaped #' => [
            "cn=a,dc=x\\#'01'B",
            "cn=a,dc=x\\#'01'B",
            null,
        ];
        yield 'an escaped backslash before the #' => [
            "cn=a,dc=x\\\\#'01'B",
            'cn=a,dc=x\\\\',
            "'01'B",
        ];
        yield 'an escaped backslash then an escaped #' => [
            "cn=a,dc=x\\\\\\#'01'B",
            "cn=a,dc=x\\\\\\#'01'B",
            null,
        ];
    }
}
