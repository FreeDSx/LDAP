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
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\ResponseInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\CramMD5Options;
use FreeDSx\Sasl\Options\PlainOptions;
use FreeDSx\Sasl\Options\ScramOptions;
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
     * The stock client never puts these credentials in an initial bind, so the request is sent raw.
     */
    private function sendRawBind(SaslBindRequest $request): ResponseInterface
    {
        $queue = new ClientQueue(new SocketPool(
            (new SocketPoolOptions(
                (new SocketOptions())
                    ->setPort(TestWorker::port())
                    ->setTimeoutConnect(1),
            ))->setServers(['127.0.0.1']),
        ));

        $queue->sendMessage(new LdapMessageRequest(
            1,
            $request,
        ));
        $response = $queue->getMessage(1)->getResponse();
        $queue->close();

        return $response;
    }
}
