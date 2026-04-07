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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind\Sasl;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchangeInput;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\SaslContext;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class SaslExchangeTest extends TestCase
{
    /**
     * Using 'PLAIN' as the mechanism name so that the real MechanismOptionsBuilderFactory
     * can produce a PlainMechanismOptionsBuilder. The mock challenge ignores the option
     * array, so the specific mechanism does not affect the exchange-loop behavior under test.
     */
    private const MECH = 'PLAIN';

    private SaslExchange $subject;

    private ServerQueue&MockObject $mockQueue;

    private ChallengeInterface&MockObject $mockChallenge;

    protected function setUp(): void
    {
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockChallenge = $this->createMock(ChallengeInterface::class);

        $mockAuthenticator = $this->createMock(PasswordAuthenticatableInterface::class);

        $this->subject = new SaslExchange(
            queue: $this->mockQueue,
            responseFactory: new ResponseFactory(),
            optionsBuilderFactory: new MechanismOptionsBuilderFactory($mockAuthenticator),
            authenticator: $mockAuthenticator,
        );
    }

    private function makeInput(?string $initialCredentials = null): SaslExchangeInput
    {
        return new SaslExchangeInput(
            challenge: $this->mockChallenge,
            mechName: self::MECH,
            initialMessage: new LdapMessageRequest(1, new SaslBindRequest(self::MECH)),
            initialCredentials: $initialCredentials,
        );
    }

    private function makeContext(
        bool $isComplete,
        bool $isAuthenticated = true,
        ?string $response = null,
    ): SaslContext {
        return (new SaslContext())
            ->setIsComplete($isComplete)
            ->setIsAuthenticated($isAuthenticated)
            ->setResponse($response);
    }

    public function test_it_breaks_immediately_on_invalid_proof(): void
    {
        // Context is complete but not authenticated (e.g. SCRAM e=invalid-proof).
        // The loop must break without sending SASL_BIND_IN_PROGRESS.
        $this->mockChallenge
            ->expects(self::once())
            ->method('challenge')
            ->willReturn($this->makeContext(
                isComplete: true,
                isAuthenticated: false,
                response: 'e=invalid-proof'
            ));

        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        $result = $this->subject->run($this->makeInput());

        self::assertFalse($result->getContext()->isAuthenticated());
    }

    public function test_it_breaks_on_stale_context_response(): void
    {
        // CRAM-MD5 pattern: after validation the mechanism leaves the old server-challenge
        // as the response instead of clearing it. The stale-response guard detects this and
        // breaks without sending a spurious second round.
        $this->mockChallenge
            ->expects(self::exactly(2))
            ->method('challenge')
            ->willReturnOnConsecutiveCalls(
                $this->makeContext(isComplete: false, response: 'server-challenge'),
                $this->makeContext(isComplete: true, response: 'server-challenge'), // stale
            );

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage'); // only the first SASL_BIND_IN_PROGRESS

        $this->mockQueue
            ->expects(self::once())
            ->method('getMessage')
            ->willReturn(new LdapMessageRequest(2, new SaslBindRequest(self::MECH, 'client-response')));

        $result = $this->subject->run($this->makeInput());

        self::assertTrue($result->getContext()->isAuthenticated());
        // Username credentials are set from the client response received in round 1.
        self::assertSame(
            'client-response',
            $result->getUsernameCredentials()
        );
    }

    public function test_it_breaks_on_context_already_complete_at_top_of_loop(): void
    {
        // DIGEST-MD5 pattern: server sends a server-final (isComplete=true, response!=null),
        // client sends an empty ack, and on the next loop iteration the context is already
        // complete so we break before calling challenge() again.
        $this->mockChallenge
            ->expects(self::exactly(2))
            ->method('challenge')
            ->willReturnOnConsecutiveCalls(
                $this->makeContext(isComplete: false, response: 'server-challenge'),
                $this->makeContext(isComplete: true, response: 'rspauth=xyz'), // server-final
            );

        // Two sendMessage calls: one challenge prompt + one server-final.
        $this->mockQueue
            ->expects(self::exactly(2))
            ->method('sendMessage');

        $this->mockQueue
            ->expects(self::exactly(2))
            ->method('getMessage')
            ->willReturnOnConsecutiveCalls(
                new LdapMessageRequest(2, new SaslBindRequest(self::MECH, 'client-response')),
                new LdapMessageRequest(3, new SaslBindRequest(self::MECH)), // empty ack
            );

        $result = $this->subject->run($this->makeInput());

        self::assertTrue($result->getContext()->isAuthenticated());
        // The last message is the empty ack (message ID 3).
        self::assertSame(
            3,
            $result->getLastMessage()->getMessageId(),
        );
    }

    public function test_it_tracks_username_credentials_from_first_non_null_response(): void
    {
        // Initial credentials are null; username credentials should come from the
        // first non-null response received from the client.
        $this->mockChallenge
            ->method('challenge')
            ->willReturnOnConsecutiveCalls(
                $this->makeContext(isComplete: false, response: 'server-challenge'),
                $this->makeContext(isComplete: true, response: 'server-challenge'), // stale
            );

        $this->mockQueue->method('sendMessage');
        $this->mockQueue
            ->method('getMessage')
            ->willReturn(new LdapMessageRequest(2, new SaslBindRequest('TEST', 'username-in-response')));

        $result = $this->subject->run($this->makeInput());

        self::assertSame(
            'username-in-response',
            $result->getUsernameCredentials()
        );
    }

    public function test_it_preserves_initial_credentials_as_username_credentials(): void
    {
        // When credentials are present in the initial bind (e.g. PLAIN), they become
        // the username credentials without waiting for a client response.
        $this->mockChallenge
            ->expects(self::once())
            ->method('challenge')
            ->willReturn($this->makeContext(isComplete: true, isAuthenticated: true, response: null));

        // isComplete && response==null → responseIsNew = (null !== null) = false → stale break.
        $this->mockQueue->expects(self::never())->method('sendMessage');

        $result = $this->subject->run($this->makeInput(initialCredentials: 'authzid\x00user\x00pass'));

        self::assertSame(
            'authzid\x00user\x00pass',
            $result->getUsernameCredentials()
        );
    }

    public function test_it_throws_protocol_error_when_non_sasl_request_received_mid_exchange(): void
    {
        $this->mockChallenge
            ->method('challenge')
            ->willReturn($this->makeContext(isComplete: false, response: 'server-challenge'));

        $this->mockQueue
            ->expects(self::exactly(2))
            ->method('sendMessage'); // SASL_BIND_IN_PROGRESS + error response

        $this->mockQueue
            ->expects(self::once())
            ->method('getMessage')
            ->willReturn(new LdapMessageRequest(2, new SimpleBindRequest('cn=user', 'pass')));

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::PROTOCOL_ERROR);

        $this->subject->run($this->makeInput());
    }
}
