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

namespace Tests\Unit\FreeDSx\Ldap\Server\Subentry;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Subentry\SubentryDetector;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use PHPUnit\Framework\TestCase;

final class SubentryDetectorTest extends TestCase
{
    private Entry $subentry;

    private Entry $ordinary;

    protected function setUp(): void
    {
        $this->subentry = Entry::fromArray(
            'cn=policy,dc=foo,dc=bar',
            [
                'objectClass' => 'subentry',
                'cn' => 'policy',
            ],
        );
        $this->ordinary = Entry::fromArray(
            'cn=alice,dc=foo,dc=bar',
            [
                'objectClass' => 'inetOrgPerson',
                'cn' => 'alice',
            ],
        );
    }

    public function test_it_recognizes_a_subentry(): void
    {
        self::assertTrue(SubentryDetector::isSubentry($this->subentry));
    }

    public function test_it_does_not_recognize_an_ordinary_entry(): void
    {
        self::assertFalse(SubentryDetector::isSubentry($this->ordinary));
    }

    public function test_the_object_class_match_ignores_case(): void
    {
        $entry = Entry::fromArray(
            'cn=policy,dc=foo,dc=bar',
            ['objectClass' => 'SubEntry'],
        );

        self::assertTrue(SubentryDetector::isSubentry($entry));
    }

    public function test_an_entry_without_an_object_class_is_not_a_subentry(): void
    {
        self::assertFalse(SubentryDetector::isSubentry(Entry::fromArray('cn=odd,dc=foo,dc=bar')));
    }

    public function test_hide_selects_only_ordinary_entries(): void
    {
        self::assertFalse(SubentryDetector::isVisibleUnder(
            $this->subentry,
            SubentryVisibility::Hide,
        ));
        self::assertTrue(SubentryDetector::isVisibleUnder(
            $this->ordinary,
            SubentryVisibility::Hide,
        ));
    }

    public function test_only_selects_just_subentries(): void
    {
        self::assertTrue(SubentryDetector::isVisibleUnder(
            $this->subentry,
            SubentryVisibility::Only,
        ));
        self::assertFalse(SubentryDetector::isVisibleUnder(
            $this->ordinary,
            SubentryVisibility::Only,
        ));
    }

    public function test_all_selects_both_populations(): void
    {
        self::assertTrue(SubentryDetector::isVisibleUnder(
            $this->subentry,
            SubentryVisibility::All,
        ));
        self::assertTrue(SubentryDetector::isVisibleUnder(
            $this->ordinary,
            SubentryVisibility::All,
        ));
    }
}
