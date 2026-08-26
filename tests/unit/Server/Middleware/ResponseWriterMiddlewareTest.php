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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Middleware\ResponseWriterMiddleware;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\StreamMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\StubMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\ThrowingMiddlewareHandler;

final class ResponseWriterMiddlewareTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private ReadBackendInterface&MockObject $mockBackend;

    private AccessControlInterface&MockObject $mockAccessControl;

    private TokenInterface&MockObject $mockToken;

    private ResponseWriterMiddleware $subject;

    /**
     * @var list<LdapMessageResponse>
     */
    private array $sent = [];

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(ReadBackendInterface::class);
        $this->mockAccessControl = $this->createMock(AccessControlInterface::class);
        $this->mockToken = $this->createMock(TokenInterface::class);

        $this->mockQueue
            ->method('sendMessages')
            ->willReturnCallback(function (iterable $responses): ServerQueue {
                foreach ($responses as $response) {
                    if ($response instanceof LdapMessageResponse) {
                        $this->sent[] = $response;
                    }
                }

                return $this->mockQueue;
            });

        $this->subject = new ResponseWriterMiddleware(
            new ResponseWriter($this->mockQueue),
            $this->mockBackend,
            $this->mockAccessControl,
        );
    }

    public function test_it_resolves_a_successful_outcome_without_rendering_an_error(): void
    {
        $result = OperationOutcomeResult::succeeded();

        $stream = $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=foo,dc=bar')),
            new StubMiddlewareHandler($result),
        );

        self::assertSame(
            $result,
            $stream->outcome(),
        );
        self::assertSame(
            [],
            $this->sent,
        );
    }

    public function test_it_renders_the_response_for_a_thrown_exception_and_does_not_rethrow(): void
    {
        $stream = $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=foo,dc=bar')),
            new ThrowingMiddlewareHandler(new OperationException(
                'Unwilling.',
                ResultCode::UNWILLING_TO_PERFORM,
            )),
        );

        self::assertSame(
            OperationOutcome::Failed,
            $stream->outcome()->outcome(),
        );

        $response = $this->firstSent()?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            ResultCode::UNWILLING_TO_PERFORM,
            $response->getResultCode(),
        );
    }

    public function test_a_mid_stream_failure_is_answered_after_the_entries_already_written(): void
    {
        $entry = new LdapMessageResponse(1, new SearchResultEntry(Entry::create('cn=a,dc=bar')));

        $this->subject->process(
            $this->contextFor((new SearchRequest(Filters::present('cn')))->base('dc=bar')),
            new StreamMiddlewareHandler(ResponseStream::streaming(
                (function () use ($entry): Generator {
                    yield $entry;

                    throw new OperationException('Backend failed.', ResultCode::OPERATIONS_ERROR);
                })(),
                static fn(): SearchOperationResult => throw new OperationException('unreached'),
            )),
        );

        // The already-produced entry went out, then the failure rendered as the search's terminal.
        self::assertSame(
            $entry,
            $this->sent[0] ?? null,
        );
        $done = $this->sent[1]->getResponse() ?? null;
        self::assertInstanceOf(SearchResultDone::class, $done);
        self::assertSame(
            ResultCode::OPERATIONS_ERROR,
            $done->getResultCode(),
        );
    }

    public function test_it_keeps_a_matched_dn_the_token_may_see(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(Entry::create('dc=bar'));
        $this->mockAccessControl
            ->method('filterEntry')
            ->willReturn(Entry::create('dc=bar'));

        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=missing,dc=bar')),
            new ThrowingMiddlewareHandler($this->noSuchObject(new Dn('dc=bar'))),
        );

        $response = $this->firstSent()?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            'dc=bar',
            $response->getDn()->toString(),
        );
    }

    public function test_it_drops_a_matched_dn_the_access_control_hides(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(Entry::create('dc=bar'));
        $this->mockAccessControl
            ->method('filterEntry')
            ->willReturn(null);

        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=missing,dc=bar')),
            new ThrowingMiddlewareHandler($this->noSuchObject(new Dn('dc=bar'))),
        );

        $response = $this->firstSent()?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            '',
            $response->getDn()->toString(),
        );
    }

    public function test_it_drops_a_matched_dn_when_the_backend_has_no_ancestor(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn(null);

        $this->subject->process(
            $this->contextFor(new DeleteRequest('cn=missing,dc=bar')),
            new ThrowingMiddlewareHandler($this->noSuchObject(new Dn('dc=bar'))),
        );

        $response = $this->firstSent()?->getResponse();
        self::assertInstanceOf(DeleteResponse::class, $response);
        self::assertSame(
            '',
            $response->getDn()->toString(),
        );
    }

    private function noSuchObject(Dn $matchedDn): OperationException
    {
        return new OperationException(
            'No such object.',
            ResultCode::NO_SUCH_OBJECT,
            null,
            $matchedDn,
        );
    }

    private function firstSent(): ?LdapMessageResponse
    {
        return $this->sent[0] ?? null;
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(
            new LdapMessageRequest(1, $request),
            $this->mockToken,
        );
    }
}
