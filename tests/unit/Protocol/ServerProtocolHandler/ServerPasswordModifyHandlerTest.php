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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerPasswordModifyHandler;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\PasswordModifyOperationResult;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyService;
use FreeDSx\Ldap\Server\PasswordModify\PasswordModifyTargetResolver;
use FreeDSx\Ldap\Server\Token\AnonToken;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * Covers the transport seam: decoding, response building, and error mapping. The use case itself is exercised by
 * {@see \Tests\Unit\FreeDSx\Ldap\Server\PasswordModify\PasswordModifyServiceTest}.
 */
final class ServerPasswordModifyHandlerTest extends TestCase
{
    private LdapBackendInterface&MockObject $mockBackend;

    private ServerPasswordModifyHandler $subject;

    private Entry $userEntry;

    private BindToken $userToken;

    protected function setUp(): void
    {
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $mockWriteHandler = $this->createMock(WriteHandlerInterface::class);

        $this->userEntry = new Entry(
            new Dn('cn=user,dc=foo,dc=bar'),
            new Attribute('userPassword', '12345'),
        );
        $this->userToken = BindToken::fromDn(
            'cn=user,dc=foo,dc=bar',
        );

        $this->subject = new ServerPasswordModifyHandler(
            service: new PasswordModifyService(
                targetResolver: new PasswordModifyTargetResolver(
                    $this->mockBackend,
                    $this->createMock(BindNameResolverInterface::class),
                ),
                accessControl: $this->createMock(AccessControlInterface::class),
                writeDispatcher: $mockWriteHandler,
                hashService: new PasswordHashService(hashCost: 4),
            ),
        );
    }

    public function test_self_service_change_sends_success_response(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn($this->userEntry);

        $stream = $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, '12345', 'newpass'),
            ),
            $this->userToken,
        );

        $response = $this->singleResponse($stream->messages);
        self::assertInstanceOf(PasswordModifyResponse::class, $response);
        self::assertNull($response->getGeneratedPassword());

        $outcome = $stream->outcome();
        self::assertInstanceOf(PasswordModifyOperationResult::class, $outcome);
        self::assertSame(
            OperationOutcome::Succeeded,
            $outcome->outcome(),
        );
    }

    public function test_server_generated_password_is_returned_in_response(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn($this->userEntry);

        $stream = $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, '12345', null),
            ),
            $this->userToken,
        );

        $response = $this->singleResponse($stream->messages);
        self::assertInstanceOf(PasswordModifyResponse::class, $response);
        self::assertSame(
            16,
            strlen((string) $response->getGeneratedPassword()),
        );
    }

    public function test_anonymous_token_is_rejected_with_unwilling_to_perform(): void
    {
        $stream = $this->subject->handleRequest(
            new LdapMessageRequest(1, new PasswordModifyRequest()),
            new AnonToken(),
        );

        self::assertSame(
            ResultCode::UNWILLING_TO_PERFORM,
            $this->singleResponse($stream->messages)->getResultCode(),
        );
    }

    public function test_an_operation_error_is_sent_as_a_standard_response(): void
    {
        $this->mockBackend
            ->method('get')
            ->willReturn($this->userEntry);

        $stream = $this->subject->handleRequest(
            new LdapMessageRequest(
                1,
                new PasswordModifyRequest(null, 'wrongpass', 'newpass'),
            ),
            $this->userToken,
        );

        self::assertSame(
            ResultCode::INVALID_CREDENTIALS,
            $this->singleResponse($stream->messages)->getResultCode(),
        );

        $outcome = $stream->outcome();
        self::assertInstanceOf(PasswordModifyOperationResult::class, $outcome);
        self::assertSame(
            OperationOutcome::Failed,
            $outcome->outcome(),
        );
    }

    /**
     * @param iterable<LdapMessageResponse> $messages
     */
    private function singleResponse(iterable $messages): LdapResult
    {
        $messages = [...$messages];
        self::assertCount(
            1,
            $messages,
        );
        $response = $messages[0]->getResponse();
        self::assertInstanceOf(
            LdapResult::class,
            $response,
        );

        return $response;
    }
}
