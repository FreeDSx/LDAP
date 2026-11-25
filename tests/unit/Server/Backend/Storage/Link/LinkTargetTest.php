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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Link;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkTarget;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use function str_repeat;

final class LinkTargetTest extends TestCase
{
    #[DataProvider('splitProvider')]
    public function test_a_value_carrying_a_uid_is_split_into_the_name_and_the_uid(
        string $value,
        string $name,
        string $uid,
    ): void {
        $target = LinkTarget::of(
            $value,
            true,
        );

        self::assertSame(
            [$name, $uid],
            [$target->name, $target->uid],
        );
    }

    public function test_a_value_of_a_type_carrying_no_uid_is_all_name(): void
    {
        $target = LinkTarget::of(
            "cn=a,dc=x#'01'B",
            false,
        );

        self::assertSame(
            ["cn=a,dc=x#'01'B", "cn=a,dc=x#'01'b", ''],
            [$target->name, $target->lcDn, $target->uid],
        );
    }

    public function test_two_spellings_of_one_link_share_an_identity(): void
    {
        self::assertSame(
            self::carrying("CN=A, DC=X#'01'B")->identity(),
            self::carrying("cn=a,dc=x#'01'b")->identity(),
        );
    }

    public function test_an_absent_uid_and_an_empty_one_are_different_links(): void
    {
        self::assertNotSame(
            self::carrying('cn=a,dc=x')->identity(),
            self::carrying("cn=a,dc=x#''B")->identity(),
        );
    }

    public function test_a_uid_is_not_mistaken_for_a_dn_ending_in_the_same_characters(): void
    {
        self::assertNotSame(
            self::carrying("cn=a,dc=x#'01'B")->identity(),
            self::carrying('cn=a,dc=x#01')->identity(),
        );
    }

    #[DataProvider('valueProvider')]
    public function test_a_stored_link_is_given_back_with_the_uid_it_keeps(
        string $uid,
        string $value,
    ): void {
        self::assertSame(
            $value,
            LinkTarget::valueOf(
                'cn=A,dc=x',
                $uid,
            ),
        );
    }

    public function test_a_uid_at_the_longest_length_kept_is_storable(): void
    {
        $this->expectNotToPerformAssertions();

        self::carrying(self::withUidOf(LinkTarget::MAX_UID_BITS))->assertStorable();
    }

    public function test_a_uid_past_the_longest_length_kept_is_refused(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        self::carrying(self::withUidOf(LinkTarget::MAX_UID_BITS + 1))->assertStorable();
    }

    /**
     * @return Generator<string, array{string, string, string}>
     */
    public static function splitProvider(): Generator
    {
        yield 'no uid' => [
            'cn=a,dc=x',
            'cn=a,dc=x',
            '',
        ];
        yield 'an empty bit string' => [
            "cn=a,dc=x#''B",
            'cn=a,dc=x',
            '#',
        ];
        yield 'bits' => [
            "cn=a,dc=x#'0101'B",
            'cn=a,dc=x',
            '#0101',
        ];
        yield 'a closing lowercase b' => [
            "cn=a,dc=x#'0101'b",
            'cn=a,dc=x',
            '#0101',
        ];
        yield 'a tail that is not a bit string' => [
            "cn=a,dc=x#'0102'B",
            "cn=a,dc=x#'0102'B",
            '',
        ];
        yield 'a # inside an RDN value' => [
            'cn=a#b,dc=x',
            'cn=a#b,dc=x',
            '',
        ];
    }

    /**
     * @return Generator<string, array{string, string}>
     */
    public static function valueProvider(): Generator
    {
        yield 'no uid' => [
            '',
            'cn=A,dc=x',
        ];
        yield 'an empty bit string' => [
            '#',
            "cn=A,dc=x#''B",
        ];
        yield 'bits' => [
            '#0101',
            "cn=A,dc=x#'0101'B",
        ];
    }

    private static function carrying(string $value): LinkTarget
    {
        return LinkTarget::of(
            $value,
            true,
        );
    }

    private static function withUidOf(int $bits): string
    {
        return "cn=a,dc=x#'" . str_repeat(
            '1',
            $bits,
        ) . "'B";
    }
}
