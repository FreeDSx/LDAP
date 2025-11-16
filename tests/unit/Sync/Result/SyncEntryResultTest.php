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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use PHPUnit\Framework\TestCase;

final class SyncEntryResultTest extends TestCase
{
    private SyncEntryResult $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncEntryResult(new EntryResult(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('cn=foo')),
                new SyncStateControl(
                    SyncStateControl::STATE_ADD,
                    'foo',
                    'bar'
                )
            )
        ));
    }

    public function test_it_should_get_the_entry(): void
    {
        self::assertEquals(
            new Entry('cn=foo'),
            $this->subject->getEntry(),
        );
    }

    public function test_it_should_get_the_sync_state(): void
    {
        self::assertSame(
            SyncStateControl::STATE_ADD,
            $this->subject->getState(),
        );
    }

    public function test_it_should_get_the_cookie(): void
    {
        self::assertSame(
            'bar',
            $this->subject->getCookie(),
        );
    }

    public function test_it_should_get_the_entry_uuid(): void
    {
        self::assertSame(
            'foo',
            $this->subject->getEntryUuid(),
        );
    }

    public function test_it_should_be_able_to_check_what_the_state_is(): void
    {
        self::assertTrue(
            $this->subject->isState(SyncStateControl::STATE_ADD)
        );
    }

    public function test_it_should_be_able_to_check_what_the_state_is_not(): void
    {
        self::assertFalse(
            $this->subject->isState(SyncStateControl::STATE_MODIFY)
        );
    }


    public function test_it_should_tell_if_it_is_for_a_present_state(): void
    {
        $this->subject = new SyncEntryResult(
            new EntryResult(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry(new Entry('cn=foo')),
                    new SyncStateControl(
                        SyncStateControl::STATE_PRESENT,
                        'foo',
                        'bar'
                    )
                )
            )
        );

        self::assertTrue($this->subject->isPresent());
    }

    public function test_it_should_tell_if_it_is_for_a_add_state(): void
    {
        $this->subject = new SyncEntryResult(new EntryResult(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('cn=foo')),
                new SyncStateControl(
                    SyncStateControl::STATE_ADD,
                    'foo',
                    'bar'
                )
            )
        ));

        self::assertTrue($this->subject->isAdd());
    }

    public function test_it_should_tell_if_it_is_for_a_modify_state(): void
    {
        $this->subject = new SyncEntryResult(
            new EntryResult(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry(new Entry('cn=foo')),
                    new SyncStateControl(
                        SyncStateControl::STATE_MODIFY,
                        'foo',
                        'bar'
                    )
                )
            )
        );

        self::assertTrue($this->subject->isModify());
    }

    public function test_it_should_tell_if_it_is_for_a_delete_state(): void
    {
        $this->subject = new SyncEntryResult(
            new EntryResult(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry(new Entry('cn=foo')),
                    new SyncStateControl(
                        SyncStateControl::STATE_DELETE,
                        'foo',
                        'bar'
                    )
                )
            )
        );

        self::assertTrue($this->subject->isDelete());
    }

    public function test_it_should_get_the_raw_message(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('cn=foo')),
                new SyncStateControl(
                    SyncStateControl::STATE_ADD,
                    'foo',
                    'bar'
                )
            ),
            $this->subject->getMessage(),
        );
    }

    public function test_it_should_throw_an_error_if_there_is_no_sync_state_control(): void
    {
        self::expectException(RuntimeException::class);
        self::expectExceptionMessage('Expected a SyncStateControl, but none was found.');

        $this->subject = new SyncEntryResult(new EntryResult(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('cn=foo')),
            )
        ));

        $this->subject->getState();
    }
}
