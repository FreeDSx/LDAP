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

use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\ResponseInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Socket\SocketOptions;
use FreeDSx\Socket\SocketPool;
use FreeDSx\Socket\SocketPoolOptions;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

/**
 * Covers mechanisms whose security depends on the server contributing randomness before a client proof is accepted.
 */
final class SaslChallengeIntegrationTest extends ServerTestCase
{
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
     * The stock client never puts these credentials in an initial bind, so the request is sent raw.
     */
    private function sendRawBind(SaslBindRequest $request): ResponseInterface
    {
        $queue = new ClientQueue(new SocketPool(
            (new SocketPoolOptions(
                (new SocketOptions())
                    ->setPort(10389)
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
