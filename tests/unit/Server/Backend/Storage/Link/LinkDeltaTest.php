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

use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use PHPUnit\Framework\TestCase;

final class LinkDeltaTest extends TestCase
{
    private const BOB = 'cn=Bob,dc=example,dc=com';

    private const CAROL = 'cn=Carol,dc=example,dc=com';

    public function test_the_same_values_on_both_sides_leave_the_links_untouched(): void
    {
        $delta = LinkDelta::between(
            ['seealso' => [self::BOB]],
            ['seealso' => [self::BOB]],
        );

        self::assertTrue($delta->isUntouched());
    }

    public function test_a_value_held_only_after_is_added(): void
    {
        $delta = LinkDelta::between(
            ['seealso' => [self::BOB]],
            ['seealso' => [self::BOB, self::CAROL]],
        );

        self::assertFalse($delta->isUntouched());
        self::assertSame(
            [self::CAROL],
            $delta->added('seeAlso'),
        );
        self::assertSame(
            [],
            $delta->removed('seeAlso'),
        );
    }

    public function test_a_value_held_only_before_is_removed(): void
    {
        $delta = LinkDelta::between(
            ['seealso' => [self::BOB], 'member' => [self::CAROL]],
            ['member' => [self::CAROL]],
        );

        self::assertSame(
            [self::BOB],
            $delta->removed('seeAlso'),
        );
        self::assertSame(
            ['seealso'],
            $delta->names(),
        );
    }

    public function test_two_spellings_of_one_target_leave_the_links_untouched(): void
    {
        $delta = LinkDelta::between(
            ['seealso' => [self::BOB]],
            ['seealso' => ['CN=bob, DC=Example, DC=com']],
        );

        self::assertTrue($delta->isUntouched());
    }
}
