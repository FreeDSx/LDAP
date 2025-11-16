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

use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientExtendedOperationHandler;
use FreeDSx\Ldap\Protocol\Factory\ExtendedResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientExtendedOperationHandlerTest extends TestCase
{
    private ClientExtendedOperationHandler $subject;

    private ClientQueue&MockObject $mockQueue;

    private ExtendedResponseFactory&MockObject $mockResponseFactory;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ClientQueue::class);
        $this->mockResponseFactory = $this->createMock(ExtendedResponseFactory::class);

        $this->subject = new ClientExtendedOperationHandler(
            $this->mockQueue,
            $this->mockResponseFactory,
        );
    }

    public function test_it_should_handle_a_response(): void
    {
        $this->mockResponseFactory
            ->method('has')
            ->willReturn(false);

        $this->mockResponseFactory
            ->expects($this->never())
            ->method('get');

        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0), 'bar', 'foo'));

        self::assertSame(
            $response,
            $this->subject->handleResponse(
                new LdapMessageRequest(1, new ExtendedRequest('foo', 'bar')),
                $response,
            )
        );
    }

    public function test_it_should_handle_an_extended_response_that_has_a_mapped_class(): void
    {
        $extendedResponse = new PasswordModifyResponse(new LdapResult(0));

        $this->mockResponseFactory
            ->method('has')
            ->willReturn(true);
        $this->mockResponseFactory
            ->expects($this->once())
            ->method('get')
            ->willReturn($extendedResponse);

        $request = new ExtendedRequest('foo', 'bar');
        $extendedRequest = new LdapMessageRequest(1, $request);
        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0), 'bar'));

        $this->mockQueue
            ->expects($this->once())
            ->method('sendMessage')
            ->with($this->equalTo($extendedRequest));
        $this->mockQueue
            ->method('getMessage')
            ->willReturn($response);

        self::assertInstanceOf(
            PasswordModifyResponse::class,
            $this->subject->handleRequest($extendedRequest)?->getResponse()
        );
    }
}
