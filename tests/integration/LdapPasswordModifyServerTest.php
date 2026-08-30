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

namespace Tests\Integration\FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use Tests\Support\FreeDSx\Ldap\LdapBackendStorageCommand;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

final class LdapPasswordModifyServerTest extends ServerTestCase
{
    use RawClientQueueTrait;

    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private const USER_PASSWORD = '12345';

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();

        $this->createServerProcess(
            'tcp',
            [
                '--storage=sqlite',
                '--manager',
            ],
        );
    }

    public function testAnonymousIsRejected(): void
    {
        // The server-level auth guard fires before the handler, returning INSUFFICIENT_ACCESS_RIGHTS.
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INSUFFICIENT_ACCESS_RIGHTS);

        $this->ldapClient()->sendAndReceive(
            new PasswordModifyRequest(null, null, 'newpass'),
        );
    }

    public function testSelfServicePasswordChange(): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        $this->ldapClient()->sendAndReceive(
            new PasswordModifyRequest(null, self::USER_PASSWORD, 'newpass123'),
        );

        $verifyClient = $this->buildClient('tcp');
        $verifyClient->bind(
            self::USER_DN,
            'newpass123',
        );
        $verifyClient->unbind();

        $this->assertStoredPasswordIsHashed();
    }

    public function testServerGeneratedPassword(): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        /** @var PasswordModifyResponse $response */
        $response = $this->ldapClient()
            ->sendAndReceive(new PasswordModifyRequest(null, self::USER_PASSWORD, null))
            ->getResponse();

        $this->assertInstanceOf(
            PasswordModifyResponse::class,
            $response,
        );

        $generated = $response->getGeneratedPassword();

        $this->assertNotNull($generated);
        $this->assertSame(
            16,
            strlen($generated),
        );

        $verifyClient = $this->buildClient('tcp');
        $verifyClient->bind(
            self::USER_DN,
            $generated,
        );
        $verifyClient->unbind();

        $this->assertStoredPasswordIsHashed();
    }

    /**
     * RFC 3062 2.1: a request value carries one or more fields, so one naming nothing cannot rotate a password.
     */
    public function testARequestNamingNoFieldIsRejected(): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        try {
            $this->ldapClient()->sendAndReceive(new PasswordModifyRequest());
            $this->fail('A password modify naming no field should have been refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }

        // The bound identity's password is untouched, which is the point of the refusal.
        $verifyClient = $this->buildClient('tcp');
        $verifyClient->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );
        $verifyClient->unbind();
    }

    public function testExplicitIdentityPasswordChange(): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        $this->ldapClient()->sendAndReceive(
            new PasswordModifyRequest(self::USER_DN, null, 'resetpass'),
        );

        $verifyClient = $this->buildClient('tcp');
        $verifyClient->bind(
            self::USER_DN,
            'resetpass',
        );
        $verifyClient->unbind();

        $this->assertStoredPasswordIsHashed();
    }

    public function testWrongOldPasswordReturnsInvalidCredentials(): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->ldapClient()->sendAndReceive(
            new PasswordModifyRequest(null, 'wrongpassword', 'newpass'),
        );
    }

    public function testAFailedPasswordModifyNamesNoResponseOid(): void
    {
        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            new PasswordModifyRequest(null, null, 'newpass'),
        ));

        $response = $queue->getMessage(1)->getResponse();
        $queue->close();

        self::assertInstanceOf(
            ExtendedResponse::class,
            $response,
        );
        self::assertSame(
            ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            $response->getResultCode(),
        );
        self::assertNull($response->getName());
    }

    private function assertStoredPasswordIsHashed(): void
    {
        $manager = $this->buildClient('tcp');
        $manager->bind(
            LdapBackendStorageCommand::MANAGER_DN,
            LdapBackendStorageCommand::MANAGER_PASSWORD,
        );

        $entry = $manager->read(
            self::USER_DN,
            ['userPassword'],
        );
        $manager->unbind();

        $this->assertNotNull($entry);
        $this->assertStringStartsWith(
            '{BCRYPT}',
            (string) $entry->get('userPassword')?->firstValue(),
        );
    }
}
