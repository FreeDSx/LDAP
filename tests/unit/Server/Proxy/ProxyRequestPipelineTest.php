<?php

declare(strict_types=1);

namespace Tests\Unit\FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\DecodeFailureResponder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Proxy\ProxyRequestPipeline;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ProxyRequestPipelineTest extends TestCase
{
    private ServerProtocolHandlerInterface&MockObject $startTlsHandler;

    private MiddlewareHandlerInterface&MockObject $forwarder;

    private ProxyRequestPipeline $subject;

    protected function setUp(): void
    {
        $this->startTlsHandler = $this->createMock(ServerProtocolHandlerInterface::class);
        $this->forwarder = $this->createMock(MiddlewareHandlerInterface::class);
        $this->subject = new ProxyRequestPipeline(
            $this->startTlsHandler,
            $this->forwarder,
            new ResponseWriter(
                $queue = $this->createMock(ServerQueue::class),
                new DecodeFailureResponder($queue),
            ),
        );
    }

    public function test_it_handles_start_tls_locally(): void
    {
        $this->startTlsHandler
            ->expects(self::once())
            ->method('handleRequest')
            ->willReturn(ResponseStream::none(OperationOutcomeResult::succeeded()));
        $this->forwarder
            ->expects(self::never())
            ->method('handle');

        $this->subject->handle($this->contextFor(
            new ExtendedRequest(ExtendedRequest::OID_START_TLS),
        ));
    }

    public function test_it_forwards_everything_else(): void
    {
        $this->forwarder
            ->expects(self::once())
            ->method('handle')
            ->willReturn(ResponseStream::none(OperationOutcomeResult::succeeded()));
        $this->startTlsHandler
            ->expects(self::never())
            ->method('handleRequest');

        $this->subject->handle($this->contextFor(
            new DeleteRequest('cn=foo,dc=bar'),
        ));
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(
            new LdapMessageRequest(1, $request),
            $this->createMock(TokenInterface::class),
        );
    }
}
