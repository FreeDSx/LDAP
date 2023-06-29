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

namespace spec\FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use PhpSpec\ObjectBehavior;

class SyncEntryResultSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(new EntryResult(
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

    public function it_should_get_the_entry(): void
    {
        $this->getEntry()
            ->shouldBeLike(new Entry('cn=foo'));
    }

    public function it_should_get_the_sync_state(): void
    {
        $this->getState()
            ->shouldBeEqualTo(SyncStateControl::STATE_ADD);
    }

    public function it_should_get_the_cookie(): void
    {
        $this->getCookie()
            ->shouldBeEqualTo('bar');
    }

    public function it_should_get_the_entry_uuid(): void
    {
        $this->getEntryUuid()
            ->shouldBeEqualTo('foo');
    }

    public function it_should_be_able_to_check_what_the_state_is(): void
    {
        $this->isState(SyncStateControl::STATE_ADD)
            ->shouldBeEqualTo(true);
    }

    public function it_should_be_able_to_check_what_the_state_is_not(): void
    {
        $this->isState(SyncStateControl::STATE_MODIFY)
            ->shouldBeEqualTo(false);
    }


    public function it_should_tell_if_it_is_for_a_present_state(): void
    {
        $this->beConstructedWith(new EntryResult(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('cn=foo')),
                new SyncStateControl(
                    SyncStateControl::STATE_PRESENT,
                    'foo',
                    'bar'
                )
            )
        ));

        $this->isPresent()
            ->shouldBeEqualTo(true);
    }

    public function it_should_tell_if_it_is_for_a_add_state(): void
    {
        $this->beConstructedWith(new EntryResult(
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

        $this->isAdd()
            ->shouldBeEqualTo(true);
    }

    public function it_should_tell_if_it_is_for_a_modify_state(): void
    {
        $this->beConstructedWith(new EntryResult(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('cn=foo')),
                new SyncStateControl(
                    SyncStateControl::STATE_MODIFY,
                    'foo',
                    'bar'
                )
            )
        ));

        $this->isModify()
            ->shouldBeEqualTo(true);
    }

    public function it_should_tell_if_it_is_for_a_delete_state(): void
    {
        $this->beConstructedWith(new EntryResult(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('cn=foo')),
                new SyncStateControl(
                    SyncStateControl::STATE_DELETE,
                    'foo',
                    'bar'
                )
            )
        ));

        $this->isDelete()
            ->shouldBeEqualTo(true);
    }

    public function it_should_get_the_raw_message(): void
    {
        $this->getMessage()
            ->shouldBeLike(new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('cn=foo')),
                new SyncStateControl(
                    SyncStateControl::STATE_ADD,
                    'foo',
                    'bar'
                )
            ));
    }

    public function it_should_thrown_an_error_if_there_is_no_sync_state_control(): void
    {
        $this->beConstructedWith(new EntryResult(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('cn=foo')),
            )
        ));

        $this->shouldThrow(new RuntimeException('Expected a SyncStateControl, but none was found.'))
            ->during('getState');
    }
}
