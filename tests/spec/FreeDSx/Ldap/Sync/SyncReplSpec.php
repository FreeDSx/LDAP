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

namespace spec\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Result\SyncReferralResult;
use FreeDSx\Ldap\Sync\SyncRepl;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SyncReplSpec extends ObjectBehavior
{
    public function let(LdapClient $client): void
    {
        $this->beConstructedWith($client);
    }

    public function it_is_initializable(): void
    {
        $this->shouldHaveType(SyncRepl::class);
    }

    public function it_should_poll_for_changes(LdapClient $client): void
    {
        $client->sendAndReceive(
            Argument::any(),
            Argument::that(function (SyncRequestControl $control): bool {
                return $control->getMode() === SyncRequestControl::MODE_REFRESH_ONLY;
            }),
            Argument::any(),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo')
            ));

        $this->poll();
    }

    public function it_should_listen_for_changes(LdapClient $client): void
    {
        $client->sendAndReceive(
            Argument::any(),
            Argument::that(function (SyncRequestControl $control): bool {
                return $control->getMode() === SyncRequestControl::MODE_REFRESH_AND_PERSIST;
            }),
            Argument::any(),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo')
            ));

        $this->listen();
    }

    public function it_should_use_a_filter_if_specified(LdapClient $client): void
    {
        $this->useFilter(Filters::present('foo'));

        $client->sendAndReceive(
            Argument::that(function (SyncRequest $request): bool {
                return $request->getFilter()->toString() === Filters::present('foo')->toString();
            }),
            Argument::any(),
            Argument::any(),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo')
            ));

        $this->poll();
    }

    public function it_should_use_a_sync_request_if_specified(LdapClient $client): void
    {
        $syncRequest = new SyncRequest(Filters::present('foo'));

        $this->useRequest($syncRequest);

        $client->sendAndReceive(
            Argument::exact($syncRequest),
            Argument::any(),
            Argument::any(),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo')
            ));

        $this->poll();
    }

    public function it_should_use_added_controls_if_specified(LdapClient $client): void
    {
        $control = new Control('foo');

        $this->controls()->add($control);

        $client->sendAndReceive(
            Argument::any(),
            Argument::any(),
            Argument::any(),
            Argument::exact($control),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo')
            ));

        $this->poll();
    }

    public function it_should_use_the_cookie_if_specified(LdapClient $client): void
    {
        $this->useCookie('tasty');

        $client->sendAndReceive(
            Argument::any(),
            Argument::that(function (SyncRequestControl $control): bool {
                return $control->getCookie() === 'tasty';
            }),
            Argument::any(),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo')
            ));

        $this->poll();
    }

    public function it_should_use_the_entry_handler_specified(LdapClient $client): void
    {
        $handler = fn(SyncEntryResult $result) => $result->getEntry();

        $client->sendAndReceive(
            Argument::that(function (SyncRequest $request) use ($handler) : bool {
                return $request->getEntryHandler() === $handler;
            }),
            Argument::any(),
            Argument::any(),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo')
            ));

        $this->poll($handler);
    }

    public function it_should_use_the_referral_handler_specified(LdapClient $client): void
    {
        $handler = fn(SyncReferralResult $result) => $result->getReferrals();

        $this->useReferralHandler($handler);

        $client->sendAndReceive(
            Argument::that(function (SyncRequest $request) use ($handler) : bool {
                return $request->getReferralHandler() === $handler;
            }),
            Argument::any(),
            Argument::any(),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo')
            ));

        $this->poll();
    }

    public function it_should_use_the_idSet_handler_specified(LdapClient $client): void
    {
        $handler = fn(SyncIdSetResult $result) => $result->getEntryUuids();

        $this->useIdSetHandler($handler);

        $client->sendAndReceive(
            Argument::that(function (SyncRequest $request) use ($handler) : bool {
                return $request->getIdSetHandler() === $handler;
            }),
            Argument::any(),
            Argument::any(),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0),
                new SyncDoneControl('foo')
            ));

        $this->poll();
    }

    public function it_should_throw_an_exception_if_a_sync_done_control_is_not_returned(LdapClient $client): void
    {
        $client->sendAndReceive(
            Argument::any(),
            Argument::any(),
            Argument::any(),
        )->shouldBeCalledOnce()
            ->willReturn(new LdapMessageResponse(
                1,
                new SearchResultDone(0)
            ));

        $this->shouldThrow(
            new ProtocolException(sprintf(
                'Expected a "%s" control, but none was received.',
                SyncDoneControl::class,
            ))
        )->during('poll');
    }
}
