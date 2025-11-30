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

use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerWhoAmIHandler;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerWhoAmIHandlerTest extends TestCase
{
    private ServerQueue&MockObject $mockQueue;

    private ServerWhoAmIHandler $subject;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);

        $this->subject = new ServerWhoAmIHandler($this->mockQueue);
    }

    public function test_it_should_handle_a_who_am_i_when_there_is_a_token_with_a_DN_name(): void
    {
        $request = new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(new LdapMessageResponse(
                2,
                new ExtendedResponse(new LdapResult(0), null, 'dn:cn=foo,dc=foo,dc=bar')
            )));

        $this->subject->handleRequest(
            $request,
            new BindToken('cn=foo,dc=foo,dc=bar', '12345'),
        );
    }

    public function test_it_should_handle_a_who_am_i_when_there_is_a_token_with_a_non_DN_name(): void
    {
        $request = new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(new LdapMessageResponse(
                2,
                new ExtendedResponse(new LdapResult(0), null, 'u:foo@bar.local')
            )));

        $this->subject->handleRequest(
            $request,
            new BindToken('foo@bar.local', '12345'),
        );
    }

    public function test_it_should_handle_a_who_am_i_when_there_is_no_token_yet(): void
    {
        $request = new LdapMessageRequest(2, new ExtendedRequest(ExtendedRequest::OID_WHOAMI));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo(new LdapMessageResponse(
                2,
                new ExtendedResponse(new LdapResult(0), null, '')
            )));

        $this->mockQueue
            ->method('getMessage')
            ->willReturn(new LdapMessageRequest(
                2,
                new ExtendedRequest(ExtendedRequest::OID_WHOAMI)
            ));

        $this->subject->handleRequest(
            $request,
            new AnonToken(),
        );
    }
}
