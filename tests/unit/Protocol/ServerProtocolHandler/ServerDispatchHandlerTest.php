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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerDispatchHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerDispatchHandlerTest extends TestCase
{
    private ServerDispatchHandler $subject;

    private RequestHandlerInterface&MockObject $mockRequestHandler;

    private ServerQueue&MockObject $mockQueue;

    private TokenInterface&MockObject $mockToken;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockRequestHandler = $this->createMock(RequestHandlerInterface::class);

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();

        $this->subject = new ServerDispatchHandler(
            $this->mockQueue,
            $this->mockRequestHandler,
        );
    }

    public function test_it_should_send_an_add_request_to_the_request_handler(): void
    {
        $add = new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar')));

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('add')
            ->with(self::anything(), $add->getRequest());

        $this->subject->handleRequest(
            $add,
            $this->mockToken,
        );
    }

    public function test_it_should_send_a_delete_request_to_the_request_handler(): void
    {
        $delete = new LdapMessageRequest(1, new DeleteRequest('cn=foo,dc=bar'));

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('delete')
            ->with(self::anything(), $delete->getRequest());

        $this->subject->handleRequest(
            $delete,
            $this->mockToken,
        );
    }

    public function test_it_should_send_a_modify_request_to_the_request_handler(): void
    {
        $modify = new LdapMessageRequest(1, new ModifyRequest('cn=foo,dc=bar', Change::add('foo', 'bar')));

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('modify')
            ->with(self::anything(), $modify->getRequest());

        $this->subject->handleRequest(
            $modify,
            $this->mockToken,
        );
    }

    public function test_it_should_send_a_modify_dn_request_to_the_request_handler(): void
    {
        $modifyDn = new LdapMessageRequest(1, new ModifyDnRequest('cn=foo,dc=bar', 'cn=bar', true));

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('modifyDn')
            ->with(self::anything(), $modifyDn->getRequest());

        $this->subject->handleRequest(
            $modifyDn,
            $this->mockToken,
        );
    }

    public function test_it_should_send_an_extended_request_to_the_request_handler(): void
    {
        $ext = new LdapMessageRequest(1, new ExtendedRequest('foo', 'bar'));

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('extended')
            ->with(self::anything(), $ext->getRequest());

        $this->subject->handleRequest(
            $ext,
            $this->mockToken,
        );
    }

    public function test_it_should_send_a_compare_request_to_the_request_handler(): void
    {
        $compare = new LdapMessageRequest(1, new CompareRequest('cn=foo,dc=bar', Filters::equal('foo', 'bar')));

        $this->mockRequestHandler
            ->expects($this->once())
            ->method('compare')
            ->with(self::anything(), $compare->getRequest())
            ->willReturn(true);

        $this->subject->handleRequest(
            $compare,
            $this->mockToken,
        );
    }

    public function test_it_should_throw_an_operation_exception_if_the_request_is_unsupported(): void
    {
        $request = new LdapMessageRequest(2, new AbandonRequest(1));

        self::expectException(OperationException::class);

        $this->subject->handleRequest(
            $request,
            $this->mockToken
        );
    }
}
