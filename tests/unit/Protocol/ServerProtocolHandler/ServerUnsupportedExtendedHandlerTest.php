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
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerUnsupportedExtendedHandler;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerUnsupportedExtendedHandlerTest extends TestCase
{
    private ServerUnsupportedExtendedHandler $subject;

    private TokenInterface&MockObject $mockToken;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->subject = new ServerUnsupportedExtendedHandler();
    }

    public function test_it_returns_protocol_error_without_naming_a_response(): void
    {
        $oid = '1.2.3.4.5.6.7.8.9';
        $request = new LdapMessageRequest(
            42,
            new ExtendedRequest($oid),
        );

        $stream = $this->subject->handleRequest(
            $request,
            $this->mockToken,
        );

        $this->assertEquals(
            [new LdapMessageResponse(
                42,
                new ExtendedResponse(
                    new LdapResult(
                        ResultCode::PROTOCOL_ERROR,
                        '',
                        sprintf('The extended operation "%s" is not supported.', $oid),
                    ),
                ),
            )],
            [...$stream->messages],
        );
    }

    public function test_it_ignores_non_critical_unsupported_controls(): void
    {
        $request = new LdapMessageRequest(
            7,
            new ExtendedRequest('1.2.3.4.5'),
            new Control('1.2.3.4', false),
        );

        $stream = $this->subject->handleRequest(
            $request,
            $this->mockToken,
        );

        $this->assertCount(
            1,
            [...$stream->messages],
        );
    }
}
