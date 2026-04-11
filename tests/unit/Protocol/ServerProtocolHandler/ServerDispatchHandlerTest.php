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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerDispatchHandlerTest extends TestCase
{
    private ServerDispatchHandler $subject;

    private LdapBackendInterface&MockObject $mockBackend;

    private WriteHandlerInterface&MockObject $mockWriteHandler;

    private ServerQueue&MockObject $mockQueue;

    private TokenInterface&MockObject $mockToken;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockWriteHandler = $this->createMock(WriteHandlerInterface::class);

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();

        $this->mockWriteHandler
            ->method('supports')
            ->willReturn(true);

        $this->subject = new ServerDispatchHandler(
            queue: $this->mockQueue,
            backend: $this->mockBackend,
            writeDispatcher: new WriteOperationDispatcher($this->mockWriteHandler),
        );
    }

    public function test_it_dispatches_write_requests_through_the_write_handler(): void
    {
        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $this->mockWriteHandler
            ->expects(self::once())
            ->method('handle')
            ->with(self::isInstanceOf(WriteRequestInterface::class));

        $this->subject->handleRequest($add, $this->mockToken);
    }

    public function test_it_propagates_operation_exceptions_from_the_write_handler(): void
    {
        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $this->mockWriteHandler
            ->method('handle')
            ->willThrowException(new OperationException(
                'Entry already exists.',
                ResultCode::ENTRY_ALREADY_EXISTS,
            ));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

        $this->subject->handleRequest($add, $this->mockToken);
    }

    public function test_it_delegates_compare_to_the_backend(): void
    {
        $filter = Filters::equal('foo', 'bar');
        $compare = new LdapMessageRequest(1, new CompareRequest('cn=foo,dc=bar', $filter));

        $this->mockWriteHandler
            ->expects(self::never())
            ->method('handle');

        $this->mockBackend
            ->expects(self::once())
            ->method('compare')
            ->with(
                self::isInstanceOf(Dn::class),
                self::isInstanceOf(EqualityFilter::class),
            )
            ->willReturn(true);

        $this->subject->handleRequest($compare, $this->mockToken);
    }

    public function test_it_propagates_operation_exceptions_from_backend_compare(): void
    {
        $compare = new LdapMessageRequest(1, new CompareRequest('cn=foo,dc=bar', Filters::equal('foo', 'bar')));

        $this->mockBackend
            ->method('compare')
            ->willThrowException(new OperationException(
                'No such object: cn=foo,dc=bar',
                ResultCode::NO_SUCH_OBJECT,
            ));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->handleRequest($compare, $this->mockToken);
    }

    public function test_it_throws_unwilling_to_perform_when_no_write_handler_supports_the_operation(): void
    {
        $subject = new ServerDispatchHandler(
            queue: $this->mockQueue,
            backend: $this->mockBackend,
            writeDispatcher: new WriteOperationDispatcher(),
        );

        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $subject->handleRequest($add, $this->mockToken);
    }

    public function test_it_throws_an_operation_exception_for_unsupported_requests(): void
    {
        $request = new LdapMessageRequest(2, new AbandonRequest(1));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::NO_SUCH_OPERATION);

        $this->subject->handleRequest($request, $this->mockToken);
    }

    public function test_it_sends_delete_through_the_write_handler(): void
    {
        $delete = new LdapMessageRequest(1, new DeleteRequest('cn=foo,dc=bar'));

        $this->mockWriteHandler
            ->expects(self::once())
            ->method('handle')
            ->with(self::isInstanceOf(WriteRequestInterface::class));

        $this->subject->handleRequest($delete, $this->mockToken);
    }
}
