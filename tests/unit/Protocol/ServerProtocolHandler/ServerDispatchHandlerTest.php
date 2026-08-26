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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Write\Routing\WriteRequestRouter;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use FreeDSx\Ldap\Server\Operation\CompareOperationResult;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerDispatchHandlerTest extends TestCase
{
    private ServerDispatchHandler $subject;

    private ReadBackendInterface&MockObject $mockBackend;

    private WriteHandlerInterface&MockObject $mockWriteHandler;

    private TokenInterface&MockObject $mockToken;

    private AccessControlInterface&MockObject $mockAccessControl;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockBackend = $this->createMock(ReadBackendInterface::class);
        $this->mockWriteHandler = $this->createMock(WriteHandlerInterface::class);
        $this->mockAccessControl = $this->createMock(AccessControlInterface::class);

        $this->subject = new ServerDispatchHandler(
            backend: $this->mockBackend,
            router: new WriteRequestRouter($this->mockWriteHandler),
            accessControl: $this->mockAccessControl,
            schema: new Schema(),
        );
    }

    public function test_it_dispatches_write_requests_through_the_write_handler(): void
    {
        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $this->mockWriteHandler
            ->expects(self::once())
            ->method('handle')
            ->with(self::isInstanceOf(WriteRequestInterface::class));

        $outcome = $this->subject->handleRequest($add, $this->mockToken)->outcome();

        self::assertInstanceOf(WriteOperationResult::class, $outcome);
        self::assertSame(
            OperationOutcome::Succeeded,
            $outcome->outcome(),
        );
    }

    public function test_it_lets_operation_exceptions_from_the_write_handler_bubble(): void
    {
        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $this->mockWriteHandler
            ->method('handle')
            ->willThrowException(new OperationException(
                'Entry already exists.',
                ResultCode::ENTRY_ALREADY_EXISTS,
            ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ENTRY_ALREADY_EXISTS);

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

        $outcome = $this->subject->handleRequest($compare, $this->mockToken)->outcome();

        self::assertInstanceOf(CompareOperationResult::class, $outcome);
    }

    public function test_it_lets_operation_exceptions_from_backend_compare_bubble(): void
    {
        $compare = new LdapMessageRequest(1, new CompareRequest('cn=foo,dc=bar', Filters::equal('foo', 'bar')));

        $this->mockBackend
            ->method('compare')
            ->willThrowException(new OperationException(
                'No such object: cn=foo,dc=bar',
                ResultCode::NO_SUCH_OBJECT,
            ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->handleRequest($compare, $this->mockToken);
    }

    public function test_a_write_the_handler_refuses_surfaces_its_result_code(): void
    {
        $this->mockWriteHandler
            ->method('handle')
            ->willThrowException(new OperationException(
                'This operation is not supported.',
                ResultCode::UNWILLING_TO_PERFORM,
            ));

        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->subject->handleRequest($add, $this->mockToken);
    }

    public function test_it_throws_for_unsupported_requests(): void
    {
        $request = new LdapMessageRequest(2, new AbandonRequest(1));

        $this->expectException(OperationException::class);

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

    public function test_it_sends_modify_dn_through_the_write_handler(): void
    {
        $modifyDn = new LdapMessageRequest(
            1,
            new ModifyDnRequest('cn=foo,dc=bar', 'cn=baz', true),
        );

        $this->mockWriteHandler
            ->expects(self::once())
            ->method('handle')
            ->with(self::isInstanceOf(WriteRequestInterface::class));

        $this->subject->handleRequest(
            $modifyDn,
            $this->mockToken,
        );
    }

    public function test_non_critical_unsupported_control_does_not_cause_an_error(): void
    {
        $request = new LdapMessageRequest(
            1,
            new DeleteRequest('cn=foo,dc=bar'),
            new Control('1.2.3.4.5', criticality: false),
        );

        $this->mockWriteHandler
            ->expects(self::once())
            ->method('handle');

        $this->subject->handleRequest(
            $request,
            $this->mockToken,
        );
    }
}
