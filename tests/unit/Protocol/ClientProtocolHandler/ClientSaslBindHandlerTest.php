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
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\DigestMD5Options;
use FreeDSx\Sasl\SaslContext;
use FreeDSx\Sasl\SaslInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ClientSaslBindHandlerTest extends TestCase
{
    private LdapMessageResponse $saslChallenge;

    private LdapMessageResponse $saslComplete;

    private SaslInterface&MockObject $mockSasl;

    private ClientQueue&MockObject $mockQueue;

    private RootDseLoader&MockObject $mockRootDseLoader;

    private MechanismInterface&MockObject $mockMech;

    private ChallengeInterface&MockObject $mockChallenge;

    private ClientSaslBindHandler $subject;

    protected function setUp(): void
    {
        $this->mockSasl = $this->createMock(SaslInterface::class);
        $this->mockQueue = $this->createMock(ClientQueue::class);
        $this->mockRootDseLoader = $this->createMock(RootDseLoader::class);
        $this->mockMech = $this->createMock(MechanismInterface::class);
        $this->mockChallenge = $this->createMock(ChallengeInterface::class);

        $this->mockQueue
            ->method('sendMessage')
            ->willReturnSelf();
        $this->mockQueue
            ->method('generateId')
            ->willReturnOnConsecutiveCalls(2, 3, 4, 5, 6);

        $this->saslChallenge = new LdapMessageResponse(
            1,
            new BindResponse(new LdapResult(ResultCode::SASL_BIND_IN_PROGRESS)),
        );
        $this->saslComplete = new LdapMessageResponse(
            2,
            new BindResponse(new LdapResult(ResultCode::SUCCESS), 'foo'),
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
        $saslBind = Operations::bindSasl();
        $messageRequest = new LdapMessageRequest(1, $saslBind);

        $this->mockQueue
            ->method('getMessage')
            ->willReturnOnConsecutiveCalls(
                $this->saslChallenge,
                $this->saslComplete,
            );

        $this->mockSasl
            ->expects($this->once())
            ->method('select')
            ->with(
                [MechanismName::DIGEST_MD5, MechanismName::CRAM_MD5],
                null,
            )
            ->willReturn($this->mockMech);

        $this->mockMech
            ->method('getName')
            ->willReturn(MechanismName::DIGEST_MD5);
        $this->mockMech
            ->method('challenge')
            ->willReturn($this->mockChallenge);

        $this->mockChallenge
            ->method('challenge')
            ->willReturnOnConsecutiveCalls(
                (new SaslContext())->setResponse('foo'),
                (new SaslContext())->setResponse('foo')->setIsComplete(true),
            );

        $this->mockRootDseLoader
            ->method('load')
            ->willReturn(Entry::fromArray(
                '',
                ['supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5']],
            ));

        self::assertSame(
            $this->saslComplete,
            $this->subject->handleRequest($messageRequest),
        );
    }

    public function test_it_should_detect_a_downgrade_attack(): void
    {
        $saslBind = Operations::bindSasl();
        $messageRequest = new LdapMessageRequest(1, $saslBind);

        $this->mockQueue
            ->method('getMessage')
            ->willReturnOnConsecutiveCalls(
                $this->saslChallenge,
                $this->saslComplete,
            );

        $this->mockSasl
            ->method('select')
            ->willReturn($this->mockMech);

        $this->mockMech
            ->method('getName')
            ->willReturn(MechanismName::PLAIN);
        $this->mockMech
            ->method('challenge')
            ->willReturn($this->mockChallenge);

        $this->mockChallenge
            ->method('challenge')
            ->willReturnOnConsecutiveCalls(
                (new SaslContext())->setResponse('foo'),
                (new SaslContext())->setResponse('foo')->setIsComplete(true),
            );

        $this->mockRootDseLoader
            ->method('load')
            ->with($this->anything())
            ->willReturnOnConsecutiveCalls(
                Entry::fromArray('', [
                    'supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5'],
                ]),
                Entry::fromArray('', [
                    'supportedSaslMechanisms' => ['PLAIN'],
                ]),
                Entry::fromArray('', [
                    'supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5'],
                ]),
            );

        self::expectException(BindException::class);
        self::expectExceptionMessageMatches(
            '/Possible SASL downgrade attack detected/i',
        );

        $this->subject->handleRequest($messageRequest);
    }

    public function test_it_should_not_query_the_rootdse_if_the_mechanism_was_explicitly_specified(): void
    {
        $saslBind = Operations::bindSasl(null, MechanismName::DIGEST_MD5);
        $messageRequest = new LdapMessageRequest(1, $saslBind);

        $this->withStandardRootDseResponse();
        $this->mockQueue
            ->method('getMessage')
            ->willReturnOnConsecutiveCalls(
                $this->saslChallenge,
                $this->saslComplete,
            );

        $this->mockSasl
            ->method('get')
            ->with(MechanismName::DIGEST_MD5)
            ->willReturn($this->mockMech);

        $this->mockMech
            ->method('getName')
            ->willReturn(MechanismName::DIGEST_MD5);
        $this->mockMech
            ->method('challenge')
            ->willReturn($this->mockChallenge);

        $this->mockChallenge
            ->method('challenge')
            ->willReturnOnConsecutiveCalls(
                (new SaslContext())->setResponse('foo'),
                (new SaslContext())->setResponse('foo')->setIsComplete(true),
            );

        $this->mockRootDseLoader
            ->expects(self::never())
            ->method('load');

        self::assertSame(
            $this->saslComplete,
            $this->subject->handleRequest($messageRequest),
        );
    }

    #[DataProvider('securityLayerOptions')]
    public function test_it_refuses_a_digest_md5_bind_that_asks_for_a_security_layer(DigestMD5Options $options): void
    {
        $this->mockQueue
            ->expects(self::never())
            ->method('sendMessage');

        $this->expectException(BindException::class);
        $this->expectExceptionMessage('The SASL integrity and privacy layers are not supported. Use TLS instead.');

        $this->subject->handleRequest(new LdapMessageRequest(
            1,
            Operations::bindSasl(
                $options,
                MechanismName::DIGEST_MD5,
            ),
        ));
    }

    /**
     * @return iterable<string, array{DigestMD5Options}>
     */
    public static function securityLayerOptions(): iterable
    {
        yield 'integrity' => [(new DigestMD5Options())->setUseIntegrity(true)];
        yield 'privacy' => [(new DigestMD5Options())->setUsePrivacy(true)];
    }

    public function test_it_sends_the_initial_response_and_completes_in_a_single_round(): void
    {
        // EXTERNAL: the client's first response is carried in the initial bind and the server
        // completes immediately, so the challenge loop is never entered.
        $saslBind = Operations::bindSasl(
            null,
            MechanismName::EXTERNAL,
        );
        $messageRequest = new LdapMessageRequest(1, $saslBind);

        $this->mockQueue
            ->expects(self::once())
            ->method('getMessage')
            ->willReturn($this->saslComplete);

        $this->mockSasl
            ->method('get')
            ->with(MechanismName::EXTERNAL)
            ->willReturn($this->mockMech);
        $this->mockMech
            ->method('getName')
            ->willReturn(MechanismName::EXTERNAL);
        $this->mockMech
            ->method('challenge')
            ->willReturn($this->mockChallenge);

        $this->mockChallenge
            ->expects(self::once())
            ->method('challenge')
            ->willReturn(
                (new SaslContext())
                    ->setResponse('dn:cn=proxy,dc=foo,dc=bar')
                    ->setIsComplete(true),
            );

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
                ['supportedSaslMechanisms' => ['DIGEST-MD5', 'CRAM-MD5']],
            ));
    }
}
