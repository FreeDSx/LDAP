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

use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientStartTlsHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientStartTlsHandlerTest extends TestCase
{
    private ClientStartTlsHandler $subject;

    private ClientQueue&MockObject $mockQueue;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ClientQueue::class);

        $this->subject = new ClientStartTlsHandler($this->mockQueue);
    }

    public function test_it_should_encrypt_the_queue_if_the_message_response_is_successful(): void
    {
        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));
        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(0), ExtendedRequest::OID_START_TLS));

        $this->mockQueue
            ->expects($this->once())
            ->method('encrypt')
            ->willReturnSelf();

        self::assertNotNull($this->subject->handleResponse(
            $startTls,
            $response,
        ));
    }

    public function test_it_should_throw_an_exception_if_the_message_response_is_unsuccessful(): void
    {
        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));
        $response = new LdapMessageResponse(1, new ExtendedResponse(new LdapResult(ResultCode::UNAVAILABLE_CRITICAL_EXTENSION), ExtendedRequest::OID_START_TLS));

        $this->mockQueue
            ->expects($this->never())
            ->method('encrypt')
            ->with(true);

        self::expectException(ConnectionException::class);

        $this->subject->handleResponse(
            $startTls,
            $response,
        );
    }
}
