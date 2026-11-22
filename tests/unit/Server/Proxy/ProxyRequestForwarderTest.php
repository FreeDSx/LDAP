<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Server\Proxy;

use ArrayObject;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\IntermediateResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Proxy\ProxyRequestForwarder;
use FreeDSx\Ldap\Server\Proxy\ProxyUpstreamSession;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Socket\Exception\WriteTimeoutException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ProxyRequestForwarderTest extends TestCase
{
    private LdapClient&MockObject $client;

    private ServerQueue&MockObject $queue;

    private TokenInterface&MockObject $token;

    private ProxyUpstreamSession $session;

    private ProxyRequestForwarder $subject;

    /**
     * @var list<LdapMessageResponse>
     */
    private array $relayed = [];

    protected function setUp(): void
    {
        $this->client = $this->createMock(LdapClient::class);
        $this->queue = $this->createMock(ServerQueue::class);
        $this->token = $this->createMock(TokenInterface::class);
        $this->relayed = [];

        $this->queue
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse ...$messages): ServerQueue {
                foreach ($messages as $message) {
                    $this->relayed[] = $message;
                }

                return $this->queue;
            });

        $this->session = new ProxyUpstreamSession($this->client);
        $this->subject = new ProxyRequestForwarder(
            $this->client,
            $this->queue,
            $this->session,
        );
    }

    public function test_it_upgrades_the_upstream_link_before_forwarding_anything(): void
    {
        $forwarder = new ProxyRequestForwarder(
            $this->client,
            $this->queue,
            new ProxyUpstreamSession(
                client: $this->client,
                useStartTls: true,
            ),
        );
        $this->client
            ->method('sendAndReceive')
            ->willReturn(new LdapMessageResponse(
                99,
                new DeleteResponse(ResultCode::SUCCESS),
            ));

        $this->client
            ->expects(self::once())
            ->method('startTls');

        $forwarder->handle($this->contextFor(
            7,
            new DeleteRequest('cn=foo,dc=bar'),
        ));
    }

    public function test_it_relays_a_single_response_under_the_original_message_id(): void
    {
        $this->client
            ->method('sendAndReceive')
            ->willReturn(new LdapMessageResponse(
                99,
                new DeleteResponse(ResultCode::SUCCESS),
            ));

        $this->queue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(
                static fn(LdapMessageResponse $response): bool => $response->getMessageId() === 7,
            ));

        $result = $this->subject->handle($this->contextFor(
            7,
            new DeleteRequest('cn=foo,dc=bar'),
        ));

        self::assertSame(OperationOutcome::Succeeded, $result->outcome()->outcome());
    }

    public function test_it_relays_an_upstream_error_as_a_response(): void
    {
        $this->client
            ->method('sendAndReceive')
            ->willThrowException(new OperationException(
                'No such object',
                ResultCode::NO_SUCH_OBJECT,
            ));

        $this->queue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::callback(static function (LdapMessageResponse $response): bool {
                $result = $response->getResponse();

                return $result instanceof LdapResult
                    && $result->getResultCode() === ResultCode::NO_SUCH_OBJECT;
            }));

        $result = $this->subject->handle($this->contextFor(
            1,
            new DeleteRequest('cn=missing,dc=bar'),
        ));

        self::assertSame(OperationOutcome::Failed, $result->outcome()->outcome());
    }

    public function test_it_drops_the_upstream_connection_after_a_transport_failure(): void
    {
        $this->client
            ->method('isConnected')
            ->willReturn(true);
        $this->client
            ->method('sendAndReceive')
            ->willThrowException(new ConnectionException('The connection was idle for longer than the read timeout.'));

        $this->client
            ->expects(self::once())
            ->method('disconnect');

        $this->subject->handle($this->contextFor(
            1,
            new DeleteRequest('cn=foo,dc=bar'),
        ));

        $result = $this->relayed[0]->getResponse();
        self::assertInstanceOf(
            LdapResult::class,
            $result,
        );
        self::assertSame(
            ResultCode::UNAVAILABLE,
            $result->getResultCode(),
        );
    }

    public function test_a_client_that_stopped_reading_ends_the_session_with_its_failed_write_rather_than_an_answer(): void
    {
        $failure = new WriteTimeoutException('The write operation timed out after 30 seconds.');
        $this->client
            ->method('isConnected')
            ->willReturn(true);
        $this->client
            ->method('sendAndReceive')
            ->willThrowException(new ConnectionException('The write operation timed out after 30 seconds.'));
        $this->queue
            ->method('throwIfWriteFailed')
            ->willThrowException($failure);

        $this->client
            ->expects(self::once())
            ->method('disconnect');
        $this->queue
            ->expects(self::never())
            ->method('sendMessage');
        $this->expectExceptionObject($failure);

        $this->subject->handle($this->contextFor(
            1,
            new SearchRequest(Filters::present('objectClass')),
        ));
    }

    public function test_it_answers_an_upstream_referral_on_a_non_search_operation(): void
    {
        $referral = new LdapUrl('ldap://other.example.com/dc=sub,dc=foo,dc=bar');

        $this->client
            ->method('sendAndReceive')
            ->willThrowException(new ReferralException('go elsewhere', $referral));

        $this->subject->handle($this->contextFor(
            7,
            new DeleteRequest('cn=foo,dc=bar'),
        ));

        self::assertEquals(
            new DeleteResponse(
                ResultCode::REFERRAL,
                '',
                'go elsewhere',
                $referral,
            ),
            $this->relayed[0]->getResponse(),
        );
    }

    public function test_it_closes_both_connections_on_unbind(): void
    {
        $this->client
            ->method('isConnected')
            ->willReturn(true);
        $this->client
            ->expects(self::once())
            ->method('unbind');
        $this->queue
            ->expects(self::once())
            ->method('close');

        $this->subject->handle($this->contextFor(
            1,
            new UnbindRequest(),
        ));
    }

    public function test_an_unbind_sends_nothing_upstream_when_the_upstream_was_never_used(): void
    {
        $this->client
            ->expects(self::never())
            ->method('unbind');
        $this->queue
            ->expects(self::once())
            ->method('close');

        $this->subject->handle($this->contextFor(
            1,
            new UnbindRequest(),
        ));
    }

    public function test_an_unbind_closes_the_client_connection_when_the_upstream_is_gone(): void
    {
        $this->client
            ->method('isConnected')
            ->willReturn(true);
        $this->client
            ->method('unbind')
            ->willThrowException(new ConnectionException('gone'));
        $this->queue
            ->expects(self::once())
            ->method('close');

        $this->subject->handle($this->contextFor(
            1,
            new UnbindRequest(),
        ));
    }

    public function test_it_does_not_forward_an_abandon(): void
    {
        $this->client
            ->expects(self::never())
            ->method('sendAndReceive');

        $result = $this->subject->handle($this->contextFor(
            1,
            new AbandonRequest(2),
        ));

        self::assertSame(OperationOutcome::Succeeded, $result->outcome()->outcome());
    }

    public function test_it_relays_the_controls_an_entry_arrived_with(): void
    {
        $control = new Control('1.3.6.1.4.1.4203.1.9.1.2');
        $this->upstreamStreams(
            [
                new LdapMessageResponse(
                    99,
                    new SearchResultEntry(Entry::create('cn=alice,dc=foo,dc=bar')),
                    $control,
                ),
            ],
            ResultCode::SUCCESS,
        );

        $this->subject->handle($this->contextFor(
            7,
            $this->searchRequest(),
        ));

        self::assertEquals(
            [$control],
            $this->relayed[0]->controls()->toArray(),
        );
    }

    public function test_it_relays_a_search_result_reference(): void
    {
        $this->upstreamStreams(
            [
                new LdapMessageResponse(
                    99,
                    new SearchResultReference(new LdapUrl('ldap://elsewhere/dc=foo,dc=bar')),
                ),
            ],
            ResultCode::SUCCESS,
        );

        $this->subject->handle($this->contextFor(
            7,
            $this->searchRequest(),
        ));

        self::assertInstanceOf(
            SearchResultReference::class,
            $this->relayed[0]->getResponse(),
        );
        self::assertInstanceOf(
            SearchResultDone::class,
            $this->relayed[1]->getResponse(),
        );
    }

    public function test_it_keeps_the_entries_a_limit_exceeded_search_returned(): void
    {
        $this->upstreamStreams(
            [
                new LdapMessageResponse(
                    99,
                    new SearchResultEntry(Entry::create('cn=alice,dc=foo,dc=bar')),
                ),
            ],
            ResultCode::SIZE_LIMIT_EXCEEDED,
        );

        $this->subject->handle($this->contextFor(
            7,
            $this->searchRequest(),
        ));

        self::assertInstanceOf(
            SearchResultEntry::class,
            $this->relayed[0]->getResponse(),
        );
        self::assertEquals(
            new SearchResultDone(
                ResultCode::SIZE_LIMIT_EXCEEDED,
                '',
                'Size limit exceeded.',
            ),
            $this->relayed[1]->getResponse(),
        );
    }

    public function test_it_relays_the_controls_a_failed_search_ended_with(): void
    {
        $paging = new Control(Control::OID_PAGING);
        $this->upstreamStreams(
            [],
            ResultCode::SIZE_LIMIT_EXCEEDED,
            $paging,
        );

        $this->subject->handle($this->contextFor(
            7,
            $this->searchRequest(),
        ));

        self::assertInstanceOf(
            SearchResultDone::class,
            $this->relayed[0]->getResponse(),
        );
        self::assertEquals(
            [$paging],
            $this->relayed[0]->controls()->toArray(),
        );
    }

    public function test_it_relays_an_intermediate_message_with_its_controls_under_the_client_message_id(): void
    {
        $control = new Control('1.3.6.1.4.1.42.2.27.8.5.1');
        $cookie = new SyncNewCookie('next-cookie');
        $this->upstreamStreams(
            [new LdapMessageResponse(
                3,
                $cookie,
                $control,
            )],
            ResultCode::SUCCESS,
        );

        $this->subject->handle($this->contextFor(
            7,
            $this->searchRequest(),
        ));

        self::assertSame(
            7,
            $this->relayed[0]->getMessageId(),
        );
        self::assertSame(
            $cookie,
            $this->relayed[0]->getResponse(),
        );
        self::assertEquals(
            [$control],
            $this->relayed[0]->controls()->toArray(),
        );
    }

    #[DataProvider('searchOpenForChangesProvider')]
    public function test_a_critical_control_that_keeps_the_search_open_is_refused_without_contacting_the_upstream(
        Control $control,
    ): void {
        $this->client
            ->expects(self::never())
            ->method('sendAndReceive');

        $this->subject->handle($this->searchContextWith(
            7,
            $control->setCriticality(true),
        ));

        $response = $this->relayed[0]->getResponse();
        self::assertInstanceOf(
            SearchResultDone::class,
            $response,
        );
        self::assertSame(
            ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            $response->getResultCode(),
        );
    }

    #[DataProvider('searchOpenForChangesProvider')]
    public function test_a_non_critical_control_that_keeps_the_search_open_is_left_out_of_the_forwarded_search(
        Control $control,
    ): void {
        $other = new Control('1.3.6.1.4.1.42.2.27.8.5.1');
        $forwarded = $this->captureForwardedControls();

        $this->subject->handle($this->searchContextWith(
            7,
            $other,
            $control->setCriticality(false),
        ));

        self::assertSame(
            [$other],
            $forwarded->getArrayCopy(),
        );
    }

    /**
     * @return iterable<string, array{Control}>
     */
    public static function searchOpenForChangesProvider(): iterable
    {
        yield 'a persistent content synchronization' => [
            new SyncRequestControl(SyncRequestControl::MODE_REFRESH_AND_PERSIST),
        ];
        yield 'a persistent search' => [
            new Control(Control::OID_PERSISTENT_SEARCH),
        ];
        yield 'a change notification' => [
            new Control(Control::OID_CHANGE_NOTIFICATION),
        ];
    }

    public function test_a_persistent_sync_behind_a_sync_poll_is_still_refused(): void
    {
        $this->client
            ->expects(self::never())
            ->method('sendAndReceive');

        $this->subject->handle($this->searchContextWith(
            7,
            new SyncRequestControl(SyncRequestControl::MODE_REFRESH_ONLY),
            new SyncRequestControl(SyncRequestControl::MODE_REFRESH_AND_PERSIST),
        ));

        $response = $this->relayed[0]->getResponse();
        self::assertInstanceOf(
            SearchResultDone::class,
            $response,
        );
        self::assertSame(
            ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            $response->getResultCode(),
        );
    }

    public function test_a_sync_poll_is_forwarded_with_its_sync_control(): void
    {
        $sync = new SyncRequestControl(SyncRequestControl::MODE_REFRESH_ONLY);
        $forwarded = $this->captureForwardedControls();

        $this->subject->handle(new ServerRequestContext(
            new LdapMessageRequest(
                7,
                $this->searchRequest(),
                $sync,
            ),
            $this->token,
        ));

        self::assertSame(
            [$sync],
            $forwarded->getArrayCopy(),
        );
    }

    public function test_it_relays_the_controls_a_failed_operation_answered_with(): void
    {
        $control = new Control('1.3.6.1.4.1.42.2.27.8.5.1');
        $this->client
            ->method('sendAndReceive')
            ->willThrowException(new OperationException(
                'Unwilling.',
                ResultCode::UNWILLING_TO_PERFORM,
                controls: new ControlBag($control),
            ));

        $this->subject->handle($this->contextFor(
            7,
            new DeleteRequest('cn=foo,dc=bar'),
        ));

        self::assertEquals(
            [$control],
            $this->relayed[0]->controls()->toArray(),
        );
    }

    /**
     * Stands in for the client, which hands each result to the request's handler before raising the result code.
     *
     * @param LdapMessageResponse[] $results
     */
    private function upstreamStreams(
        array $results,
        int $resultCode,
        Control ...$doneControls,
    ): void {
        $this->client
            ->method('sendAndReceive')
            ->willReturnCallback(
                static function (SearchRequest $request) use ($results, $resultCode, $doneControls): LdapMessageResponse {
                    foreach ($results as $result) {
                        $response = $result->getResponse();

                        if ($response instanceof IntermediateResponse) {
                            $intermediateHandler = $request->getIntermediateResponseHandler()
                                ?? throw new RuntimeException('The forwarder installed no intermediate handler.');
                            $intermediateHandler($result);

                            continue;
                        }

                        if ($response instanceof SearchResultReference) {
                            $referralHandler = $request->getReferralHandler()
                                ?? throw new RuntimeException('The forwarder installed no referral handler.');
                            $referralHandler(new ReferralResult($result));

                            continue;
                        }

                        $entryHandler = $request->getEntryHandler()
                            ?? throw new RuntimeException('The forwarder installed no entry handler.');
                        $entryHandler(new EntryResult($result));
                    }

                    if ($resultCode !== ResultCode::SUCCESS) {
                        throw new OperationException(
                            'Size limit exceeded.',
                            $resultCode,
                            controls: new ControlBag(...$doneControls),
                        );
                    }

                    return new LdapMessageResponse(
                        99,
                        new SearchResponse(new LdapResult($resultCode)),
                        ...$doneControls,
                    );
                },
            );
    }

    private function searchRequest(): SearchRequest
    {
        return (new SearchRequest(Filters::present('objectClass')))
            ->base('dc=foo,dc=bar');
    }

    private function contextFor(
        int $messageId,
        RequestInterface $request,
    ): ServerRequestContext {
        return new ServerRequestContext(
            new LdapMessageRequest($messageId, $request),
            $this->token,
        );
    }

    /**
     * Answers the forwarded search with success, collecting the controls it was sent upstream with.
     *
     * @return ArrayObject<int, Control>
     */
    private function captureForwardedControls(): ArrayObject
    {
        /** @var ArrayObject<int, Control> $forwarded */
        $forwarded = new ArrayObject();
        $this->client
            ->expects(self::once())
            ->method('sendAndReceive')
            ->willReturnCallback(static function (
                RequestInterface $request,
                Control ...$controls,
            ) use ($forwarded): LdapMessageResponse {
                foreach ($controls as $control) {
                    $forwarded->append($control);
                }

                return new LdapMessageResponse(
                    99,
                    new SearchResponse(new LdapResult(ResultCode::SUCCESS)),
                );
            });

        return $forwarded;
    }

    private function searchContextWith(
        int $messageId,
        Control ...$controls,
    ): ServerRequestContext {
        return new ServerRequestContext(
            new LdapMessageRequest(
                $messageId,
                $this->searchRequest(),
                ...$controls,
            ),
            $this->token,
        );
    }
}
