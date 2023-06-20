<?php

declare(strict_types=1);

namespace spec\FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use PhpSpec\ObjectBehavior;
use spec\FreeDSx\Ldap\TestFactoryTrait;

class SyncEntryResultSpec extends ObjectBehavior
{
    use TestFactoryTrait;

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
}
