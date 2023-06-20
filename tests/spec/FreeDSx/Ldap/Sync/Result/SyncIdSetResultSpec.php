<?php

declare(strict_types=1);

namespace spec\FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PhpSpec\ObjectBehavior;

class SyncIdSetResultSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(
            new LdapMessageResponse(
                1,
                new SyncIdSet(
                    ['foo', 'bar'],
                    true,
                    'tasty'
                ),
            )
        );
    }

    public function it_should_get_the_entry_uuids(): void
    {
        $this->getEntryUuids()
            ->shouldBeEqualTo([
                'foo',
                'bar',
            ]);
    }

    public function it_should_get_the_count_of_the_set(): void
    {
        $this->count()
            ->shouldBeEqualTo(2);
    }

    public function it_should_get_the_iterable_set(): void
    {
        $this->getIterator()
            ->shouldBeLike(new \ArrayIterator([
                'foo',
                'bar',
            ]));
    }

    public function it_should_get_the_raw_message(): void
    {
        $this->getMessage()
            ->shouldBeLike(
                new LdapMessageResponse(
                    1,
                    new SyncIdSet(
                        ['foo', 'bar'],
                        true,
                        'tasty'
                    ),
                )
            );
    }

    public function it_should_get_the_cookie(): void
    {
        $this->getCookie()
            ->shouldBeEqualTo('tasty');
    }

    public function it_should_get_if_this_is_for_entry_deletes(): void
    {
        $this->beConstructedWith(
            new LdapMessageResponse(
                1,
                new SyncIdSet(
                    ['foo', 'bar'],
                    true,
                    'tasty'
                ),
            )
        );

        $this->isDeleted()
            ->shouldBeEqualTo(true);
        $this->isPresent()
            ->shouldBeEqualTo(false);
    }

    public function it_should_get_if_this_is_for_entry_that_are_present(): void
    {
        $this->beConstructedWith(
            new LdapMessageResponse(
                1,
                new SyncIdSet(
                    ['foo', 'bar'],
                    false,
                    'tasty'
                ),
            )
        );

        $this->isPresent()
            ->shouldBeEqualTo(true);
        $this->isDeleted()
            ->shouldBeEqualTo(false);
    }
}
