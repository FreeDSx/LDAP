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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\InMemoryStorage;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Write\Operation\Linked\LinkedChangeReplay;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;
use Tests\Support\FreeDSx\Ldap\Storage\UidLinkSchema;

final class LinkedChangeReplayTest extends TestCase
{
    use ServerContainerTrait;

    private const ADMINS = 'cn=Admins,dc=example,dc=com';

    private const BOB = 'cn=Bob,dc=example,dc=com';

    private const CAROL = 'cn=Carol,dc=example,dc=com';

    private LinkedChangeReplay $subject;

    private LinkedChangeReplay $uidSubject;

    protected function setUp(): void
    {
        $storage = EntryFixture::inMemoryStorage(Entry::fromArray(
            self::ADMINS,
            [
                'objectClass' => ['groupOfNames'],
                'cn' => ['Admins'],
                'member' => [self::BOB],
            ],
        ));
        $this->subject = $this->containerFor($storage)->get(LinkedChangeReplay::class);

        $linked = new LinkedAttributes(UidLinkSchema::load());
        $this->uidSubject = new LinkedChangeReplay(
            new InMemoryStorage(
                EntryFixture::allWithUuid(Entry::fromArray(
                    self::ADMINS,
                    [
                        'cn' => ['Admins'],
                        UidLinkSchema::ATTRIBUTE => [self::BOB . "#'01'B", self::BOB . "#'10'B"],
                    ],
                )),
                linkedAttributes: $linked,
            ),
            $linked,
        );
    }

    public function test_changes_applied_apart_load_none_of_the_links(): void
    {
        self::assertSame(
            0,
            $this->subject->projectionFor([self::adding(self::CAROL)])->linkCap,
        );
    }

    public function test_no_changes_applied_apart_load_every_link(): void
    {
        self::assertNull($this->subject->projectionFor([])->linkCap);
    }

    public function test_no_changes_leave_the_entry_the_whole_truth_for_its_links(): void
    {
        $delta = $this->settle();

        self::assertTrue($delta->isEmpty());
        self::assertFalse($delta->isUntouched());
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

    public function test_another_uid_on_a_held_target_is_a_value_of_its_own(): void
    {
        $delta = $this->settleUids(Change::add(
            UidLinkSchema::ATTRIBUTE,
            self::BOB . "#'11'B",
        ));

        self::assertSame(
            [self::BOB . "#'11'B"],
            $delta->added(UidLinkSchema::ATTRIBUTE),
        );
    }

    public function test_a_held_uid_spelled_another_way_is_refused_as_already_held(): void
    {
        $this->expectOperationCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->settleUids(Change::add(
            UidLinkSchema::ATTRIBUTE,
            "CN=Bob, DC=example, DC=com#'01'b",
        ));
    }

    public function test_deleting_one_uid_of_a_target_keeps_the_other_held(): void
    {
        $this->expectOperationCode(ResultCode::ATTRIBUTE_OR_VALUE_EXISTS);

        $this->settleUids(
            Change::delete(
                UidLinkSchema::ATTRIBUTE,
                self::BOB . "#'01'B",
            ),
            Change::add(
                UidLinkSchema::ATTRIBUTE,
                self::BOB . "#'10'B",
            ),
        );
    }

    public function test_deleting_a_target_without_the_uid_it_is_held_with_is_answered_as_not_held(): void
    {
        $this->expectOperationCode(ResultCode::NO_SUCH_ATTRIBUTE);

        $this->settleUids(Change::delete(
            UidLinkSchema::ATTRIBUTE,
            self::BOB,
        ));
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
        return $this->subject->settle(
            array_values($changes),
            new Dn(self::ADMINS),
        );
    }

    private function settleUids(Change ...$changes): LinkDelta
    {
        return $this->uidSubject->settle(
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
