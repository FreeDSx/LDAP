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
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerCancelHandler;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerCancelHandlerTest extends TestCase
{
    private TokenInterface&MockObject $mockToken;

    private ServerCancelHandler $subject;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->subject = new ServerCancelHandler();
    }

    public function test_it_sends_no_such_operation_when_target_already_completed(): void
    {
        $stream = $this->subject->handleRequest(
            new LdapMessageRequest(3, new CancelRequest(2)),
            $this->mockToken,
        );

        $this->assertEquals(
            [new LdapMessageResponse(
                3,
                new ExtendedResponse(new LdapResult(ResultCode::NO_SUCH_OPERATION)),
            )],
            [...$stream->messages],
        );
    }

    public function test_it_sends_cannot_cancel_when_a_cancel_names_itself(): void
    {
        $stream = $this->subject->handleRequest(
            new LdapMessageRequest(3, new CancelRequest(3)),
            $this->mockToken,
        );

        $this->assertEquals(
            [new LdapMessageResponse(
                3,
                new ExtendedResponse(new LdapResult(ResultCode::CANNOT_CANCEL)),
            )],
            [...$stream->messages],
        );
    }
}
