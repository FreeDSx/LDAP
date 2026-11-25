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
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Storage\UidLinkSchema;

final class LinkDeltaTest extends TestCase
{
    private const BOB = 'cn=Bob,dc=example,dc=com';

    private const CAROL = 'cn=Carol,dc=example,dc=com';

    private LinkedAttributes $linked;

    protected function setUp(): void
    {
        $this->linked = new LinkedAttributes(UidLinkSchema::load());
    }

    public function test_the_same_values_on_both_sides_leave_the_links_untouched(): void
    {
        $delta = LinkDelta::between(
            ['seealso' => [self::BOB]],
            ['seealso' => [self::BOB]],
            $this->linked,
        );

        self::assertTrue($delta->isUntouched());
    }

    public function test_a_value_held_only_after_is_added(): void
    {
        $delta = LinkDelta::between(
            ['seealso' => [self::BOB]],
            ['seealso' => [self::BOB, self::CAROL]],
            $this->linked,
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
            $this->linked,
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
            $this->linked,
        );

        self::assertTrue($delta->isUntouched());
    }

    public function test_a_second_uid_on_one_target_is_a_value_of_its_own(): void
    {
        $delta = LinkDelta::between(
            ['uidlink' => [self::BOB . "#'01'B"]],
            ['uidlink' => [self::BOB . "#'01'B", self::BOB . "#'10'B"]],
            $this->linked,
        );

        self::assertSame(
            [self::BOB . "#'10'B"],
            $delta->added(UidLinkSchema::ATTRIBUTE),
        );
    }

    public function test_dropping_the_uid_from_a_value_replaces_the_link(): void
    {
        $delta = LinkDelta::between(
            ['uidlink' => [self::BOB . "#'01'B"]],
            ['uidlink' => [self::BOB]],
            $this->linked,
        );

        self::assertSame(
            [self::BOB],
            $delta->added(UidLinkSchema::ATTRIBUTE),
        );
        self::assertSame(
            [self::BOB . "#'01'B"],
            $delta->removed(UidLinkSchema::ATTRIBUTE),
        );
    }

    public function test_two_spellings_of_one_target_and_uid_leave_the_links_untouched(): void
    {
        $delta = LinkDelta::between(
            ['uidlink' => [self::BOB . "#'01'B"]],
            ['uidlink' => ["CN=bob, DC=Example, DC=com#'01'b"]],
            $this->linked,
        );

        self::assertTrue($delta->isUntouched());
    }
}
