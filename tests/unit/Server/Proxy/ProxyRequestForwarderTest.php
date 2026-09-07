<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
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
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ProxyRequestForwarderTest extends TestCase
{
    private LdapClient&MockObject $client;

    private ServerQueue&MockObject $queue;

    private TokenInterface&MockObject $token;

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

        $this->subject = new ProxyRequestForwarder(
            $this->client,
            $this->queue,
        );
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

    public function test_it_closes_both_connections_on_unbind(): void
    {
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

    /**
     * Stands in for the client, which hands each result to the request's handler before raising the result code.
     *
     * @param LdapMessageResponse[] $results
     */
    private function upstreamStreams(
        array $results,
        int $resultCode,
    ): void {
        $this->client
            ->method('sendAndReceive')
            ->willReturnCallback(
                static function (SearchRequest $request) use ($results, $resultCode): LdapMessageResponse {
                    foreach ($results as $result) {
                        $response = $result->getResponse();

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
                        throw new OperationException('Size limit exceeded.', $resultCode);
                    }

                    return new LdapMessageResponse(
                        99,
                        new SearchResponse(new LdapResult($resultCode)),
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
}
