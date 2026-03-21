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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\CancelRequestException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSyncHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Result\SyncReferralResult;
use FreeDSx\Ldap\Sync\Session;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Unit\FreeDSx\Ldap\TestFactoryTrait;

final class ClientSyncHandlerTest extends TestCase
{
    use TestFactoryTrait;

    private ClientSyncHandler $subject;

    private ClientQueue&MockObject $mockQueue;

    private ClientOptions $options;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ClientQueue::class);
        $this->options = new ClientOptions();

        $this->subject = new ClientSyncHandler(
            $this->mockQueue,
            $this->options,
        );
    }

    public function test_it_should_set_a_default_DN_for_a_request_that_has_none(): void
    {
        $this->options->setBaseDn('cn=foo');

        $nockResponse = $this->createMock(LdapMessageResponse::class);
        $mockMessage = $this->createMock(LdapMessageRequest::class);
        $mockSyncRequest = $this->createMock(SyncRequest::class);

        $this->mockQueue
            ->expects($this->once())
            ->method('getMessage')
            ->willReturn($nockResponse);

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage');

        $mockMessage
            ->method('getRequest')
            ->willReturn($mockSyncRequest);
        $mockSyncRequest
            ->method('getBaseDn')
            ->willReturn(null);

        $mockSyncRequest
            ->expects($this->once())
            ->method('setBaseDn')
            ->with('cn=foo');

        $this->subject->handleRequest($mockMessage);
    }


    public function test_it_should_retrieve_results_until_it_receives_a_search_done_with_a_sync_done_control(): void
    {
        $messageTo = new LdapMessageRequest(
            1,
            new SyncRequest(),
            new SyncRequestControl(),
        );
        $response = new LdapMessageResponse(
            1,
            new SearchResultEntry(new Entry('bar'))
        );

        $entries = [
            new SearchResultEntry(new Entry('foo')),
            new SearchResultEntry(new Entry('foo')),
            new SearchResultEntry(new Entry('foo')),
        ];
        $referrals = [
            new SearchResultReference(new LdapUrl('ldap://foo')),
        ];

        $this->mockQueue
            ->expects($this->exactly(5))
            ->method('getMessage')
            ->with(1)
            ->will(self::onConsecutiveCalls(
                new LdapMessageResponse(1, $entries[0]),
                new LdapMessageResponse(1, $entries[1]),
                new LdapMessageResponse(1, $referrals[0]),
                new LdapMessageResponse(1, $entries[2]),
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(
                        0,
                        'cn=foo',
                        'bar'
                    ),
                    new SyncDoneControl('foo')
                )
            ));

        self::assertEquals(
            self::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                controls: [
                    new SyncDoneControl('foo'),
                ]
            ),
            $this->subject->handleResponse(
                $messageTo,
                $response,
            ),
        );
    }

    public function test_it_should_throw_an_exception_if_a_sync_request_control_was_not_provided(): void
    {
        self::expectExceptionObject(new RuntimeException(sprintf(
            'Expected a "%s", but there is none.',
            SyncRequestControl::class,
        )));

        $this->subject->handleResponse(
            new LdapMessageRequest(
                1,
                new SyncRequest(),
            ),
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('bar'))
            ),
        );
    }

    public function test_it_should_process_a_sync_entry(): void
    {
        $entry = new Entry('bar');
        $syncState = new SyncStateControl(
            SyncStateControl::STATE_ADD,
            'foo',
            'bar'
        );

        $entyProcessed = null;
        $handler = function (SyncEntryResult $result) use (&$entyProcessed) {
            $entyProcessed = $result->getEntry();
        };

        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useEntryHandler($handler(...)),
            new SyncRequestControl(),
        );
        $response = new LdapMessageResponse(
            1,
            new SearchResultEntry($entry),
            $syncState,
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('getMessage')
            ->with(1)
            ->willReturn(
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(
                        0,
                        'cn=foo',
                        'bar'
                    ),
                    new SyncDoneControl('foo')
                )
            );

        self::assertEquals(
            $this::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                controls: [
                    new SyncDoneControl('foo'),
                ]
            ),
            $this->subject->handleResponse(
                $messageTo,
                $response,
            )
        );
        self::assertSame(
            $entry,
            $entyProcessed,
        );
    }

    public function test_it_should_process_a_sync_id_set(): void
    {
        $setProcessed = null;
        $handler = function (SyncIdSetResult $result) use (&$setProcessed) {
            $setProcessed = $result->getEntryUuids();
        };
        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useIdSetHandler($handler(...)),
            new SyncRequestControl(),
        );
        $response = new LdapMessageResponse(
            1,
            new SyncIdSet(['bar']),
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('getMessage')
            ->with(1)
            ->willReturn(
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(
                        0,
                        'cn=foo',
                        'bar'
                    ),
                    new SyncDoneControl('foo')
                )
            );

        self::assertEquals(
            self::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                controls: [
                    new SyncDoneControl('foo'),
                ]
            ),
            $this->subject->handleResponse(
                $messageTo,
                $response,
            )
        );
        self::assertSame(
            ['bar'],
            $setProcessed,
        );
    }

    public function test_a_refresh_delete_in_progress_sets_phase_delete_and_refresh_is_not_complete(): void
    {
        $capturedSession = null;
        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useEntryHandler(function (SyncEntryResult $_result, Session $session) use (&$capturedSession): void {
                    $capturedSession = $session;
                }),
            new SyncRequestControl(),
        );

        $this->mockQueue
            ->expects($this->exactly(2))
            ->method('getMessage')
            ->with(1)
            ->willReturnOnConsecutiveCalls(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry(new Entry('bar')),
                    new SyncStateControl(SyncStateControl::STATE_ADD, 'foo'),
                ),
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(0, '', ''),
                    new SyncDoneControl(),
                ),
            );

        $this->subject->handleResponse(
            $messageTo,
            new LdapMessageResponse(1, new SyncRefreshDelete(refreshDone: false)),
        );

        self::assertSame(
            Session::PHASE_DELETE,
            $capturedSession?->getPhase()
        );
        self::assertFalse($capturedSession->isRefreshComplete());
    }

    public function test_a_refresh_delete_done_sets_null_phase_and_marks_refresh_complete(): void
    {
        $capturedSession = null;
        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useEntryHandler(function (SyncEntryResult $_result, Session $session) use (&$capturedSession): void {
                    $capturedSession = $session;
                }),
            new SyncRequestControl(),
        );

        $this->mockQueue
            ->expects($this->exactly(2))
            ->method('getMessage')
            ->with(1)
            ->willReturnOnConsecutiveCalls(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry(new Entry('bar')),
                    new SyncStateControl(SyncStateControl::STATE_ADD, 'foo'),
                ),
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(0, '', ''),
                    new SyncDoneControl(),
                ),
            );

        $this->subject->handleResponse(
            $messageTo,
            new LdapMessageResponse(1, new SyncRefreshDelete(refreshDone: true)),
        );

        self::assertNull($capturedSession?->getPhase());
        self::assertTrue($capturedSession?->isRefreshComplete());
    }

    public function test_a_refresh_present_in_progress_sets_phase_present_and_refresh_is_not_complete(): void
    {
        $capturedSession = null;
        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useEntryHandler(function (SyncEntryResult $_result, Session $session) use (&$capturedSession): void {
                    $capturedSession = $session;
                }),
            new SyncRequestControl(),
        );

        $this->mockQueue
            ->expects($this->exactly(2))
            ->method('getMessage')
            ->with(1)
            ->willReturnOnConsecutiveCalls(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry(new Entry('bar')),
                    new SyncStateControl(SyncStateControl::STATE_ADD, 'foo'),
                ),
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(0, '', ''),
                    new SyncDoneControl(),
                ),
            );

        $this->subject->handleResponse(
            $messageTo,
            new LdapMessageResponse(1, new SyncRefreshPresent(refreshDone: false)),
        );

        self::assertSame(
            Session::PHASE_PRESENT,
            $capturedSession?->getPhase()
        );
        self::assertFalse($capturedSession->isRefreshComplete());
    }

    public function test_a_refresh_present_done_sets_null_phase_and_marks_refresh_complete(): void
    {
        $capturedSession = null;
        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useEntryHandler(function (SyncEntryResult $_result, Session $session) use (&$capturedSession): void {
                    $capturedSession = $session;
                }),
            new SyncRequestControl(),
        );

        $this->mockQueue
            ->expects($this->exactly(2))
            ->method('getMessage')
            ->with(1)
            ->willReturnOnConsecutiveCalls(
                new LdapMessageResponse(
                    1,
                    new SearchResultEntry(new Entry('bar')),
                    new SyncStateControl(SyncStateControl::STATE_ADD, 'foo'),
                ),
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(0, '', ''),
                    new SyncDoneControl(),
                ),
            );

        $this->subject->handleResponse(
            $messageTo,
            new LdapMessageResponse(1, new SyncRefreshPresent(refreshDone: true)),
        );

        self::assertNull($capturedSession?->getPhase());
        self::assertTrue($capturedSession?->isRefreshComplete());
    }

    public function test_it_should_process_a_sync_referral(): void
    {
        $referral = new LdapUrl('bar');
        $syncState = new SyncStateControl(
            SyncStateControl::STATE_ADD,
            'foo',
            'bar'
        );

        $referralsProcessed = null;
        $handler = function (SyncReferralResult $result) use (&$referralsProcessed) {
            $referralsProcessed = $result->getReferrals();
        };

        $messageTo = new LdapMessageRequest(
            1,
            (new SyncRequest())
                ->useReferralHandler($handler(...)),
            new SyncRequestControl(),
        );
        $response = new LdapMessageResponse(
            1,
            new SearchResultReference($referral),
            $syncState,
        );

        $this->mockQueue
            ->expects($this->once())
            ->method('getMessage')
            ->with(1)
            ->willReturn(
                new LdapMessageResponse(
                    1,
                    new SearchResultDone(
                        0,
                        'cn=foo',
                        'bar'
                    ),
                    new SyncDoneControl('foo')
                )
            );

        self::assertEquals(
            self::makeSearchResponseFromEntries(
                dn: 'cn=foo',
                diagnostic: 'bar',
                controls: [
                    new SyncDoneControl('foo'),
                ]
            ),
            $this->subject->handleResponse(
                $messageTo,
                $response,
            )
        );
        self::assertSame(
            [$referral],
            $referralsProcessed,
        );
    }

    public function test_the_sync_done_cookie_is_captured_when_a_cancel_is_requested(): void
    {
        $syncRequest = new SyncRequest();
        $syncRequest->useEntryHandler(function (): void {
            throw new CancelRequestException();
        });

        $messageTo = new LdapMessageRequest(
            1,
            $syncRequest,
            new SyncRequestControl(),
        );

        $this->mockQueue
            ->method('generateId')
            ->willReturn(2);

        $drainCallCount = 0;
        $this->mockQueue
            ->method('getMessage')
            ->willReturnCallback(
                function () use (&$drainCallCount): LdapMessageResponse {
                    $cancelResponse = new LdapMessageResponse(
                        2,
                        new ExtendedResponse(new LdapResult(ResultCode::CANCELED)),
                    );
                    $searchDone = new LdapMessageResponse(
                        1,
                        new SearchResultDone(ResultCode::CANCELED, '', ''),
                        new SyncDoneControl('final-cookie'),
                    );
                    $drainCallCount++;

                    return $drainCallCount === 1 ? $searchDone : $cancelResponse;
                }
            );

        $result = $this->subject->handleResponse(
            $messageTo,
            new LdapMessageResponse(
                1,
                new SearchResultEntry(new Entry('foo')),
                new SyncStateControl(SyncStateControl::STATE_ADD, 'uuid'),
            ),
        );

        self::assertSame(
            'final-cookie',
            $result?->controls()->getByClass(SyncDoneControl::class)?->getCookie(),
        );
    }
}
