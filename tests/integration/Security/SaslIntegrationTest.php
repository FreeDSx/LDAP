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

namespace Tests\Integration\FreeDSx\Ldap\Security;

use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\ResponseInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\CramMD5Options;
use FreeDSx\Sasl\Options\PlainOptions;
use FreeDSx\Sasl\Options\ScramOptions;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Socket\SocketOptions;
use FreeDSx\Socket\SocketPool;
use FreeDSx\Socket\SocketPoolOptions;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\TestWorker;

final class SaslIntegrationTest extends ServerTestCase
{
    /**
     * The stored hash for cn=hashed in the harness seed, as an attacker reading the directory would obtain it.
     */
    private const STOLEN_HASH = '{SHA}JDjNt4ihTaLvLHpHhEFSdZmM1KM=';

    private const HASHED_PASSWORD = 'hashedpass';

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();

        $this->createServerProcess(
            'tcp',
            ['--sasl'],
        );
    }

    /**
     * The digest is computable offline when no challenge was issued, so it must never be verified.
     */
    public function testSaslCramMD5CredentialsInTheInitialBindAreRejected(): void
    {
        $forged = 'user ' . hash_hmac('md5', '', '12345');

        $response = $this->sendRawBind(new SaslBindRequest(
            'CRAM-MD5',
            $forged,
        ));

        $this->assertInstanceOf(
            BindResponse::class,
            $response,
        );
        $this->assertSame(
            ResultCode::INVALID_CREDENTIALS,
            $response->getResultCode(),
        );
    }

    /**
     * A client-final carries the proof, so without a client-first the server contributed no nonce to bind it to.
     */
    public function testSaslScramClientFinalWithoutClientFirstIsRejected(): void
    {
        $forged = 'c=biws,r=,p=' . base64_encode(str_repeat('a', 32));

        $response = $this->sendRawBind(new SaslBindRequest(
            'SCRAM-SHA-256',
            $forged,
        ));

        $this->assertInstanceOf(
            BindResponse::class,
            $response,
        );
        $this->assertSame(
            ResultCode::PROTOCOL_ERROR,
            $response->getResultCode(),
        );
    }

    /**
     * A mechanism keying on the stored value would otherwise make the hash itself the password.
     */
    public function testSaslCramMD5RefusesAStoredHashAsTheSharedSecret(): void
    {
        $this->expectException(BindException::class);

        $this->buildClient('tcp')->bindSasl(
            (new CramMD5Options())->setUsername('hashed')->setPassword(self::STOLEN_HASH),
            MechanismName::CRAM_MD5,
        );
    }

    public function testSaslPlainStillAuthenticatesAgainstAStoredHash(): void
    {
        $response = $this->ldapClient()->bindSasl(
            (new PlainOptions())->setUsername('hashed')->setPassword(self::HASHED_PASSWORD),
            MechanismName::PLAIN,
        )->getResponse();

        $this->assertInstanceOf(
            BindResponse::class,
            $response,
        );
        $this->assertSame(
            0,
            $response->getResultCode(),
        );
    }

    public function testSaslPlainRefusesAStoredHashAsThePassword(): void
    {
        $this->expectException(BindException::class);

        $this->buildClient('tcp')->bindSasl(
            (new PlainOptions())->setUsername('hashed')->setPassword(self::STOLEN_HASH),
            MechanismName::PLAIN,
        );
    }

    public function testSaslCramMD5RefusesAnEmptyStoredPassword(): void
    {
        $this->expectException(BindException::class);

        $this->buildClient('tcp')->bindSasl(
            (new CramMD5Options())->setUsername('empty')->setPassword(''),
            MechanismName::CRAM_MD5,
        );
    }

    public function testSaslScramRefusesAnEmptyStoredPassword(): void
    {
        $this->expectException(BindException::class);

        $this->buildClient('tcp')->bindSasl(
            (new ScramOptions())->setUsername('empty')->setPassword(''),
            MechanismName::SCRAM_SHA256,
        );
    }

    /**
     * Credentials that would otherwise authenticate, so only the message ID can account for the refusal.
     */
    public function testSaslContinuationCarryingAZeroMessageIdIsRefused(): void
    {
        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            new SaslBindRequest('CRAM-MD5'),
        ));
        $challenge = $queue->getMessage(1)->getResponse();
        self::assertInstanceOf(
            BindResponse::class,
            $challenge,
        );

        $queue->sendMessage(new LdapMessageRequest(
            0,
            new SaslBindRequest(
                'CRAM-MD5',
                'user ' . hash_hmac('md5', (string) $challenge->getSaslCredentials(), '12345'),
            ),
        ));

        try {
            $queue->getMessage();
            self::fail('The continuation was accepted.');
        } catch (UnsolicitedNotificationException $e) {
            self::assertTrue($e->isNoticeOfDisconnection());
        } finally {
            $queue->close();
        }
    }

    /**
     * RFC 4511 4.1.1 reserves disconnection for an unparseable PDU; bad credentials are an ordinary bind failure.
     */
    public function testMalformedPlainCredentialsAreAnsweredWithABindResponse(): void
    {
        $response = $this->sendRawBind(new SaslBindRequest(
            'PLAIN',
            'no-nul-separators-here',
        ));

        self::assertInstanceOf(
            BindResponse::class,
            $response,
        );
        self::assertNotSame(
            ResultCode::SUCCESS,
            $response->getResultCode(),
        );
    }

    public function testMalformedPlainCredentialsLeaveTheSessionUsable(): void
    {
        $queue = $this->rawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                new SaslBindRequest('PLAIN', 'no-nul-separators-here'),
            ));
            $queue->getMessage(1);

            $queue->sendMessage(new LdapMessageRequest(
                2,
                new SaslBindRequest('PLAIN', "\x00user\x0012345"),
            ));

            self::assertSame(
                ResultCode::SUCCESS,
                $this->resultCodeOf($queue->getMessage(2)),
            );
        } finally {
            $queue->close();
        }
    }

    /**
     * RFC 4511 4.2.1: an empty mechanism aborts the negotiation and MUST answer authMethodNotSupported.
     */
    public function testAnEmptyMechanismMidNegotiationAbortsWithAuthMethodNotSupported(): void
    {
        $queue = $this->rawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                new SaslBindRequest('CRAM-MD5'),
            ));
            self::assertSame(
                ResultCode::SASL_BIND_IN_PROGRESS,
                $this->resultCodeOf($queue->getMessage(1)),
            );

            $queue->sendMessage(new LdapMessageRequest(
                2,
                new SaslBindRequest(''),
            ));

            self::assertSame(
                ResultCode::AUTH_METHOD_UNSUPPORTED,
                $this->resultCodeOf($queue->getMessage(2)),
            );
        } finally {
            $queue->close();
        }
    }

    /**
     * RFC 4511 4.2.1 names a different mechanism as a way to abort the negotiation in progress.
     */
    public function testSwitchingMechanismMidNegotiationRestartsTheExchange(): void
    {
        $queue = $this->rawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                new SaslBindRequest('CRAM-MD5'),
            ));
            $queue->getMessage(1);

            $queue->sendMessage(new LdapMessageRequest(
                2,
                new SaslBindRequest('PLAIN', "\x00user\x0012345"),
            ));

            self::assertSame(
                ResultCode::SUCCESS,
                $this->resultCodeOf($queue->getMessage(2)),
            );
        } finally {
            $queue->close();
        }
    }

    /**
     * RFC 4513 5.2.1.2: server-final data rides out with the success rather than costing another round trip.
     */
    public function testScramReturnsServerFinalDataWithTheSuccessResponse(): void
    {
        $options = (new ScramOptions())
            ->setUsername('user')
            ->setPassword('12345');
        $challenge = (new Sasl())
            ->get(MechanismName::SCRAM_SHA256)
            ->challenge();
        $queue = $this->rawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                new SaslBindRequest(
                    'SCRAM-SHA-256',
                    $challenge->challenge(null, $options)->getResponse(),
                ),
            ));
            $first = $queue->getMessage(1)->getResponse();
            self::assertInstanceOf(
                BindResponse::class,
                $first,
            );

            $queue->sendMessage(new LdapMessageRequest(
                2,
                new SaslBindRequest(
                    'SCRAM-SHA-256',
                    $challenge->challenge($first->getSaslCredentials(), $options)->getResponse(),
                ),
            ));
            $second = $queue->getMessage(2)->getResponse();

            self::assertInstanceOf(
                BindResponse::class,
                $second,
            );
            self::assertSame(
                ResultCode::SUCCESS,
                $second->getResultCode(),
            );
            self::assertStringStartsWith(
                'v=',
                (string) $second->getSaslCredentials(),
            );
        } finally {
            $queue->close();
        }
    }

    /**
     * The stock client never puts these credentials in an initial bind, so the request is sent raw.
     */
    private function sendRawBind(SaslBindRequest $request): ResponseInterface
    {
        $queue = $this->rawQueue();

        $queue->sendMessage(new LdapMessageRequest(
            1,
            $request,
        ));
        $response = $queue->getMessage(1)->getResponse();
        $queue->close();

        return $response;
    }

    private function resultCodeOf(LdapMessageResponse $message): int
    {
        $response = $message->getResponse();
        self::assertInstanceOf(
            BindResponse::class,
            $response,
        );

        return $response->getResultCode();
    }

    private function rawQueue(): ClientQueue
    {
        return new ClientQueue(new SocketPool(
            (new SocketPoolOptions(
                (new SocketOptions())
                    ->setPort(TestWorker::port())
                    ->setTimeoutConnect(1),
            ))->setServers(['127.0.0.1']),
        ));
    }
}
