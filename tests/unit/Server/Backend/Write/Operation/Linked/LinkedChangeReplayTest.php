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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write\Operation\Linked;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Write\Operation\Linked\LinkedChangeReplay;
use FreeDSx\Ldap\Server\Backend\Write\Operation\Linked\SettledLinks;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;

final class LinkedChangeReplayTest extends TestCase
{
    use ServerContainerTrait;

    private const ADMINS = 'cn=Admins,dc=example,dc=com';

    private const BOB = 'cn=Bob,dc=example,dc=com';

    private const CAROL = 'cn=Carol,dc=example,dc=com';

    private const DAN = 'cn=Dan,dc=example,dc=com';

    private const STAFF = 'cn=Staff,dc=example,dc=com';

    private LinkedChangeReplay $subject;

    protected function setUp(): void
    {
        $storage = EntryFixture::inMemoryStorage(
            Entry::fromArray(
                self::ADMINS,
                [
                    'objectClass' => ['groupOfNames'],
                    'cn' => ['Admins'],
                    'member' => [self::BOB],
                ],
            ),
            Entry::fromArray(
                self::STAFF,
                [
                    'objectClass' => ['groupOfNames'],
                    'cn' => ['Staff'],
                    'member' => [self::BOB, self::CAROL, self::DAN],
                ],
            ),
        );
        $this->subject = $this->containerFor($storage)->get(LinkedChangeReplay::class);
    }

    public function test_no_changes_leave_the_entry_the_whole_truth_for_its_links(): void
    {
        $delta = $this->subject->settle(
            [],
            new Dn(self::ADMINS),
        )->delta;

        self::assertTrue($delta->isEmpty());
        self::assertFalse($delta->isUntouched());
    }

    public function test_the_changes_are_kept_as_supplied(): void
    {
        $changes = [
            self::adding(self::CAROL),
            self::deleting(self::CAROL),
        ];

        self::assertSame(
            $changes,
            $this->settled(...$changes)->changes,
        );
    }

    public function test_adding_to_a_held_value_counts_more_than_one(): void
    {
        self::assertSame(
            ['member' => 2],
            $this->settled(self::adding(self::CAROL))->counts,
        );
    }

    public function test_deleting_the_only_held_value_counts_none(): void
    {
        self::assertSame(
            ['member' => 0],
            $this->settled(self::deleting(self::BOB))->counts,
        );
    }

    public function test_replacing_the_only_held_value_counts_one(): void
    {
        self::assertSame(
            ['member' => 1],
            $this->settled(
                self::deleting(self::BOB),
                self::adding(self::CAROL),
            )->counts,
        );
    }

    public function test_a_count_stops_once_it_is_more_than_one(): void
    {
        self::assertSame(
            ['member' => 2],
            $this->subject->settle(
                [self::deleting(self::BOB)],
                new Dn(self::STAFF),
            )->counts,
        );
    }

    public function test_a_delete_and_an_add_net_to_both(): void
    {
        $delta = $this->settle(
            self::deleting(self::BOB),
            self::adding(self::CAROL),
        );

        self::assertSame(
            [self::CAROL],
            $delta->added('member'),
        );
        self::assertSame(
            [self::BOB],
            $delta->removed('member'),
        );
    }

    public function test_adding_then_deleting_a_value_leaves_the_links_untouched(): void
    {
        $delta = $this->settle(
            self::adding(self::CAROL),
            self::deleting(self::CAROL),
        );

        self::assertTrue($delta->isUntouched());
    }

    public function test_deleting_then_adding_a_held_value_leaves_the_links_untouched(): void
    {
        $delta = $this->settle(
            self::deleting(self::BOB),
            self::adding(self::BOB),
        );

        self::assertTrue($delta->isUntouched());
    }

    public function test_adding_a_value_again_after_deleting_it_links_it(): void
    {
        $delta = $this->settle(
            self::adding(self::CAROL),
            self::deleting(self::CAROL),
            self::adding(self::CAROL),
        );

        self::assertSame(
            [self::CAROL],
            $delta->added('member'),
        );
        self::assertSame(
            [],
            $delta->removed('member'),
        );
    }

    public function test_adding_a_value_an_earlier_change_added_is_refused(): void
    {
        $this->expectOperationCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->settle(
            self::adding(self::CAROL),
            self::adding(self::CAROL),
        );
    }

    public function test_the_same_value_twice_in_one_add_is_refused(): void
    {
        $this->expectOperationCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->settle(self::adding(
            self::CAROL,
            'CN=Carol, DC=example, DC=com',
        ));
    }

    public function test_deleting_a_value_an_earlier_change_deleted_is_refused(): void
    {
        $this->expectOperationCode(ResultCode::NO_SUCH_ATTRIBUTE);

        $this->settle(
            self::deleting(self::BOB),
            self::deleting(self::BOB),
        );
    }

    public function test_a_value_named_twice_in_one_delete_is_removed_once(): void
    {
        $delta = $this->settle(self::deleting(
            self::BOB,
            'CN=Bob, DC=example, DC=com',
        ));

        self::assertCount(
            1,
            $delta->removed('member'),
        );
    }

    public function test_deleting_a_value_that_is_not_a_dn_is_answered_as_not_held(): void
    {
        $this->expectOperationCode(ResultCode::NO_SUCH_ATTRIBUTE);

        $this->settle(self::deleting('not a dn'));
    }

    public function test_adding_a_value_that_is_not_a_dn_is_refused_for_its_syntax(): void
    {
        $this->expectOperationCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->settle(self::adding('not a dn'));
    }

    public function test_a_value_that_is_not_a_dn_added_then_deleted_is_never_held_to_its_syntax(): void
    {
        $delta = $this->settle(
            self::adding('not a dn'),
            self::deleting('not a dn'),
        );

        self::assertTrue($delta->isUntouched());
    }

    private static function adding(string ...$members): Change
    {
        return Change::add(
            'member',
            ...$members,
        );
    }

    private static function deleting(string ...$members): Change
    {
        return Change::delete(
            'member',
            ...$members,
        );
    }

    private function settle(Change ...$changes): LinkDelta
    {
        return $this->settled(...$changes)->delta;
    }

    private function settled(Change ...$changes): SettledLinks
    {
        return $this->subject->settle(
            array_values($changes),
            new Dn(self::ADMINS),
        );
    }

    private function expectOperationCode(int $code): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode($code);
    }
}
