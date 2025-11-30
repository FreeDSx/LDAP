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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientSaslBindHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\RootDseLoader;
use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\Mechanism\MechanismInterface;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\Security\SecurityLayerInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientSaslBindHandlerTest extends TestCase
{
    private LdapMessageResponse $saslChallenge;

    private LdapMessageResponse $saslComplete;

    private Sasl&MockObject $mockSasl;

    private ClientQueue&MockObject $mockQueue;

    private RootDseLoader&MockObject $mockRootDseLoader;

    private MechanismInterface&MockObject $mockMech;

    private ChallengeInterface&MockObject $mockChallenge;

    private ClientSaslBindHandler $subject;

    protected function setUp(): void
    {
        $this->mockSasl = $this->createMock(Sasl::class);
        $this->mockQueue = $this->createMock(ClientQueue::class);
        $this->mockRootDseLoader = $this->createMock(RootDseLoader::class);
        $this->mockMech = $this->createMock(MechanismInterface::class);
        $this->mockChallenge = $this->createMock(ChallengeInterface::class);

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();
        $this->mockQueue
            ->method('generateId')
            ->will($this->onConsecutiveCalls(2, 3, 4, 5, 6));

        $this->saslChallenge = new LdapMessageResponse(
            1,
            new BindResponse(new LdapResult(ResultCode::SASL_BIND_IN_PROGRESS))
        );
        $this->saslComplete = new LdapMessageResponse(
            2,
            new BindResponse(new LdapResult(ResultCode::SUCCESS), 'foo')
        );

        $this->subject = new ClientSaslBindHandler(
            $this->mockQueue,
            $this->mockRootDseLoader,
            $this->mockSasl,
        );
    }

    public function test_it_should_handle_a_sasl_bind_request(): void
    {
        $this->withStandardRootDseResponse();
        $saslBind = Operations::bindSasl(['username' => 'foo', 'password' => 'bar']);
        $messageRequest = new LdapMessageRequest(1, $saslBind);

        $this->mockQueue
            ->method('getMessage')
            ->will(self::onConsecutiveCalls(
                $this->saslChallenge,
                $this->saslComplete,
            ));

        $this->mockSasl
            ->expects($this->once())
            ->method('select')
            ->with(['DIGEST-MD5', 'CRAM-MD5'], ['username' => 'foo', 'password' => 'bar'])
            ->willReturn($this->mockMech);

        $this->mockMech
            ->method('getName')
            ->willReturn('DIGEST-MD5');
        $this->mockMech
            ->method('challenge')
            ->willReturn($this->mockChallenge);

        $this->mockChallenge
            ->method('challenge')
            ->with(self::anything(), ['username' => 'foo', 'password' => 'bar'])
            ->will($this->onConsecutiveCalls(
                (new SaslContext())->setResponse('foo'),
                (new SaslContext())->setResponse('foo')->setIsComplete(true)
            ));

        $this->mockRootDseLoader
            ->method('load')
            ->willReturn(Entry::fromArray(
                '',
                ['supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5']]
            ));

        self::assertSame(
            $this->saslComplete,
            $this->subject->handleRequest($messageRequest),
        );
    }

    public function test_it_should_detect_a_downgrade_attack(): void {
        $saslBind = Operations::bindSasl(['username' => 'foo', 'password' => 'bar']);
        $messageRequest = new LdapMessageRequest(1, $saslBind);

        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                $this->saslChallenge,
                $this->saslComplete,
            ));

        $this->mockSasl
            ->method('select')
            ->willReturn($this->mockMech);

        $this->mockMech
            ->method('getName')
            ->willReturn('PLAIN');
        $this->mockMech
            ->method('challenge')
            ->willReturn($this->mockChallenge);

        $this->mockChallenge
            ->method('challenge')
            ->with(self::anything(), ['username' => 'foo', 'password' => 'bar'])
            ->will($this->onConsecutiveCalls(
                (new SaslContext())->setResponse('foo'),
                (new SaslContext())->setResponse('foo')->setIsComplete(true)
            ));

        $this->mockRootDseLoader
            ->method('load')
            ->with($this->anything())
            ->will(self::onConsecutiveCalls(
                Entry::fromArray('', [
                    'supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5'],
                ]),
                Entry::fromArray('', [
                    'supportedSaslMechanisms' => ['PLAIN'],
                ]),
                Entry::fromArray('', [
                    'supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5'],
                ]),
            ));

        self::expectException(BindException::class);
        self::expectExceptionMessageMatches(
            '/Possible SASL downgrade attack detected/i'
        );

        $this->subject->handleRequest($messageRequest);
    }

    public function test_it_should_not_query_the_rootdse_if_the_mechanism_was_explicitly_specified(): void
    {
        $saslBind = Operations::bindSasl(['username' => 'foo', 'password' => 'bar'], 'DIGEST-MD5');
        $messageRequest = new LdapMessageRequest(1, $saslBind);

        $this->withStandardRootDseResponse();
        $this->mockQueue
            ->method('getMessage')
            ->will($this->onConsecutiveCalls(
                $this->saslChallenge,
                $this->saslComplete,
            ));

        $this->mockSasl
            ->method('get')
            ->with('DIGEST-MD5')
            ->willReturn($this->mockMech);

        $this->mockMech
            ->method('getName')
            ->willReturn('DIGEST-MD5');
        $this->mockMech
            ->method('challenge')
            ->willReturn($this->mockChallenge);

        $this->mockChallenge
            ->method('challenge')
            ->will(self::onConsecutiveCalls(
                (new SaslContext())->setResponse('foo'),
                (new SaslContext())->setResponse('foo')->setIsComplete(true)
            ));

        $this->mockRootDseLoader
            ->expects(self::never())
            ->method('load');

        self::assertSame(
            $this->saslComplete,
            $this->subject->handleRequest($messageRequest),
        );
    }

    public function test_it_should_set_the_set_the_security_layer_on_the_queue_if_one_was_negotiated(): void
    {
        $saslBind = Operations::bindSasl(['username' => 'foo', 'password' => 'bar'], 'DIGEST-MD5');
        $messageRequest = new LdapMessageRequest(1, $saslBind);

        $this->mockQueue
            ->method('getMessage')
            ->will(self::onConsecutiveCalls(
                $this->saslChallenge,
                $this->saslComplete,
            ));

        $this->mockSasl
            ->method('get')
            ->willReturn($this->mockMech);
        $this->mockMech
            ->method('getName')
            ->willReturn('DIGEST-MD5');
        $this->mockMech
            ->method('challenge')
            ->willReturn($this->mockChallenge);

        $this->mockChallenge
            ->method('challenge')
            ->will(self::onConsecutiveCalls(
                (new SaslContext())->setResponse('foo'),
                (new SaslContext())->setResponse('foo')
                    ->setHasSecurityLayer(true)
                    ->setIsAuthenticated(true)
                    ->setIsComplete(true)
            ));

        $mockSecurityLayer = $this->createMock(SecurityLayerInterface::class);
        $this->mockMech
            ->method('securityLayer')
            ->willReturn($mockSecurityLayer);

        $this->mockQueue
            ->expects(self::once())
            ->method('setMessageWrapper')
            ->willReturnSelf();

        self::assertSame(
            $this->saslComplete,
            $this->subject->handleRequest($messageRequest),
        );
    }

    private function withStandardRootDseResponse(): void
    {
        $this->mockRootDseLoader
            ->method('load')
            ->willReturn(Entry::fromArray(
                '',
                ['supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5']]
            ));

    }
}
