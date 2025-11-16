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
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerStartTlsHandlerTest extends TestCase
{
    private ServerStartTlsHandler $subject;

    private ServerQueue&MockObject $mockQueue;

    private TokenInterface&MockObject $mockToken;

    private ServerOptions $options;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->options = new ServerOptions();

        $this->subject = new ServerStartTlsHandler(
            $this->options,
            $this->mockQueue,
        );
    }

    public function test_it_should_handle_a_start_tls_request(): void
    {
        $this->options->setSslCert('foo');

        $this->mockQueue
            ->method('isEncrypted')
            ->willReturn(false);

        $this->mockQueue
            ->method('encrypt')
            ->willReturnSelf();

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(new LdapMessageResponse(
                1,
                new ExtendedResponse(
                    new LdapResult(0),
                    ExtendedRequest::OID_START_TLS
                )
            ));

        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));

        $this->subject->handleRequest(
            $startTls,
            $this->mockToken,
        );
    }

    public function test_it_should_send_back_an_error_if_the_queue_is_already_encrypted(): void
    {
        $this->options->setSslCert('foo');

        $this->mockQueue
            ->method('isEncrypted')
            ->willReturn(true);

        $this->mockQueue
            ->expects(self::never())
            ->method('encrypt');

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                1,
                new ExtendedResponse(
                    new LdapResult(ResultCode::OPERATIONS_ERROR, '', 'The current LDAP session is already encrypted.'),
                    ExtendedRequest::OID_START_TLS
                )
            )));

        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));

        $this->subject->handleRequest(
            $startTls,
            $this->mockToken,
        );
    }

    public function test_it_should_send_back_an_error_if_encryption_is_not_supported(): void
    {
        $this->mockQueue
            ->method('isEncrypted')
            ->willReturn(false);

        $this->mockQueue
            ->expects(self::never())
            ->method('encrypt');

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                1,
                new ExtendedResponse(
                    new LdapResult(ResultCode::PROTOCOL_ERROR),
                    ExtendedRequest::OID_START_TLS
                )
            )));

        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));

        $this->subject->handleRequest(
            $startTls,
            $this->mockToken,
        );
    }
}
