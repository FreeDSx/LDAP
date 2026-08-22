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
use FreeDSx\Ldap\Protocol\Queue\ConnectionControl;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerStartTlsHandler;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerStartTlsHandlerTest extends TestCase
{
    private ServerStartTlsHandler $subject;

    private ConnectionControl&MockObject $mockConnection;

    private TokenInterface&MockObject $mockToken;

    private ServerOptions $options;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockConnection = $this->createMock(ConnectionControl::class);
        $this->options = TestServerOptions::defaults();

        $this->subject = new ServerStartTlsHandler(
            $this->options,
            $this->mockConnection,
        );
    }

    public function test_it_should_handle_a_start_tls_request(): void
    {
        $this->options->getNetworkConfig()->setSslCert('foo');

        $this->mockConnection
            ->method('isEncrypted')
            ->willReturn(false);

        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));

        $stream = $this->subject->handleRequest(
            $startTls,
            $this->mockToken,
        );

        $this->assertEquals(
            [new LdapMessageResponse(
                1,
                new ExtendedResponse(
                    new LdapResult(0),
                    ExtendedRequest::OID_START_TLS,
                ),
            )],
            [...$stream->messages],
        );

        // The socket is only encrypted once the writer runs onComplete, after the SUCCESS is flushed.
        $this->mockConnection
            ->expects(self::once())
            ->method('encrypt')
            ->willReturnSelf();

        $this->assertNotNull($stream->onComplete);
        ($stream->onComplete)($this->mockConnection);
    }

    public function test_it_should_send_back_an_error_if_the_queue_is_already_encrypted(): void
    {
        $this->options->getNetworkConfig()->setSslCert('foo');

        $this->mockConnection
            ->method('isEncrypted')
            ->willReturn(true);

        $this->mockConnection
            ->expects(self::never())
            ->method('encrypt');

        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));

        $stream = $this->subject->handleRequest(
            $startTls,
            $this->mockToken,
        );

        $this->assertEquals(
            [new LdapMessageResponse(
                1,
                new ExtendedResponse(
                    new LdapResult(ResultCode::OPERATIONS_ERROR, '', 'The current LDAP session is already encrypted.'),
                    ExtendedRequest::OID_START_TLS,
                ),
            )],
            [...$stream->messages],
        );
        $this->assertNull($stream->onComplete);
    }

    public function test_it_should_send_back_an_error_if_encryption_is_not_supported(): void
    {
        $this->mockConnection
            ->method('isEncrypted')
            ->willReturn(false);

        $this->mockConnection
            ->expects(self::never())
            ->method('encrypt');

        $startTls = new LdapMessageRequest(1, new ExtendedRequest(ExtendedRequest::OID_START_TLS));

        $stream = $this->subject->handleRequest(
            $startTls,
            $this->mockToken,
        );

        $this->assertEquals(
            [new LdapMessageResponse(
                1,
                new ExtendedResponse(
                    new LdapResult(
                        ResultCode::UNAVAILABLE,
                        '',
                        'The server is not configured to provide TLS.',
                    ),
                    ExtendedRequest::OID_START_TLS,
                ),
            )],
            [...$stream->messages],
        );
        $this->assertNull($stream->onComplete);
    }
}
