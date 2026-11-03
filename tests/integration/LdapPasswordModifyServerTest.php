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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\PasswordModifyResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FreeDSx\Ldap\LdapBackendStorageCommand;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

use function str_repeat;
use function substr;

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

    public function testANewPasswordOverTheLengthLimitIsRefused(): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        try {
            $this->ldapClient()->sendAndReceive(new PasswordModifyRequest(
                null,
                self::USER_PASSWORD,
                str_repeat(
                    'a',
                    513,
                ),
            ));
            $this->fail('A new password over the length limit should have been refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }

        $verifyClient = $this->buildClient('tcp');
        $verifyClient->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );
        $verifyClient->unbind();
    }

    public function testANewPasswordHoldingANulByteBindsOnlyInFullUnderTheDefaultHashing(): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        $this->ldapClient()->sendAndReceive(new PasswordModifyRequest(
            null,
            self::USER_PASSWORD,
            "new\0password",
        ));

        $this->assertSame(
            [
                ResultCode::SUCCESS,
                ResultCode::INVALID_CREDENTIALS,
            ],
            [
                $this->bindResultCode("new\0password"),
                $this->bindResultCode('new'),
            ],
        );
    }

    public function testANewPasswordAtTheLengthLimitBindsOnlyInFullUnderTheDefaultHashing(): void
    {
        $password = str_repeat(
            'a',
            512,
        );
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        $this->ldapClient()->sendAndReceive(new PasswordModifyRequest(
            null,
            self::USER_PASSWORD,
            $password,
        ));

        $this->assertSame(
            [
                ResultCode::SUCCESS,
                ResultCode::INVALID_CREDENTIALS,
            ],
            [
                $this->bindResultCode($password),
                $this->bindResultCode(substr(
                    $password,
                    0,
                    72,
                )),
            ],
        );
    }

    public function testANewPasswordOver72BytesIsRefusedUnderBcrypt(): void
    {
        $this->restartHashingWithBcrypt();
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        try {
            $this->ldapClient()->sendAndReceive(new PasswordModifyRequest(
                null,
                self::USER_PASSWORD,
                str_repeat(
                    'a',
                    73,
                ),
            ));
            $this->fail('A new password over 72 bytes should have been refused under bcrypt.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }

        $this->assertSame(
            ResultCode::SUCCESS,
            $this->bindResultCode(self::USER_PASSWORD),
        );
    }

    public function testANewPasswordOf72BytesBindsUnderBcrypt(): void
    {
        $password = str_repeat(
            'a',
            72,
        );
        $this->restartHashingWithBcrypt();
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        $this->ldapClient()->sendAndReceive(new PasswordModifyRequest(
            null,
            self::USER_PASSWORD,
            $password,
        ));

        $this->assertSame(
            ResultCode::SUCCESS,
            $this->bindResultCode($password),
        );
    }

    public function testANewPasswordHoldingANulByteIsRefusedUnderBcrypt(): void
    {
        $this->restartHashingWithBcrypt();
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        try {
            $this->ldapClient()->sendAndReceive(new PasswordModifyRequest(
                null,
                self::USER_PASSWORD,
                "new\0password",
            ));
            $this->fail('A new password holding a NUL byte should have been refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::CONSTRAINT_VIOLATION,
                $e->getCode(),
            );
        }

        $verifyClient = $this->buildClient('tcp');
        $verifyClient->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );
        $verifyClient->unbind();
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

    public function testARequestCarryingAnUnrecognizedFieldIsRefusedAndChangesNothing(): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        try {
            $this->ldapClient()->sendAndReceive(new ExtendedRequest(
                ExtendedRequest::OID_PWD_MODIFY,
                Asn1::sequence(
                    Asn1::context(
                        2,
                        Asn1::octetString('newpass123'),
                    ),
                    Asn1::context(
                        3,
                        Asn1::octetString('extension'),
                    ),
                ),
            ));
            $this->fail('A password modify carrying an unrecognized field should have been refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }

        $verifyClient = $this->buildClient('tcp');
        $verifyClient->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );
        $verifyClient->unbind();
    }

    #[DataProvider('malformedRequestValueProvider')]
    public function testAMalformedRequestValueIsAnsweredWithoutEndingTheSession(string $value): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        try {
            $this->ldapClient()->sendAndReceive(new ExtendedRequest(
                ExtendedRequest::OID_PWD_MODIFY,
                $value,
            ));
            $this->fail('A malformed password modify value should have been refused.');
        } catch (OperationException $e) {
            $this->assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }

        $this->assertSame(
            'dn:' . self::USER_DN,
            $this->ldapClient()->whoami(),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedRequestValueProvider(): iterable
    {
        yield 'a value that is not a sequence'
            => ["\x04\x00"];
        yield 'a value that is not BER'
            => ["\x01\x02\x03"];
        yield 'an empty value'
            => [''];
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

    public function testExplicitIdentityPasswordChangeNamedByAnAliasSpelledDn(): void
    {
        $this->ldapClient()->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );

        $this->ldapClient()->sendAndReceive(
            new PasswordModifyRequest('commonName=user,dc=foo,dc=bar', null, 'aliaspass'),
        );

        $verifyClient = $this->buildClient('tcp');
        $verifyClient->bind(
            self::USER_DN,
            'aliaspass',
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

    public function testAnotherUsersOldPasswordIsRefusedWhetherRightOrWrong(): void
    {
        $this->ldapClient()->bind(
            LdapBackendStorageCommand::MANAGER_DN,
            LdapBackendStorageCommand::MANAGER_PASSWORD,
        );

        foreach ([self::USER_PASSWORD, 'guess'] as $oldPassword) {
            try {
                $this->ldapClient()->sendAndReceive(
                    new PasswordModifyRequest(self::USER_DN, $oldPassword, $oldPassword),
                );
                $this->fail('Another user\'s old password should have been refused.');
            } catch (OperationException $e) {
                $this->assertSame(
                    ResultCode::UNWILLING_TO_PERFORM,
                    $e->getCode(),
                );
            }
        }

        $verifyClient = $this->buildClient('tcp');
        $verifyClient->bind(
            self::USER_DN,
            self::USER_PASSWORD,
        );
        $verifyClient->unbind();
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
            '{ARGON2}$argon2id$v=19$m=7168,t=5,p=1$',
            (string) $entry->get('userPassword')?->firstValue(),
        );
    }

    private function restartHashingWithBcrypt(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--storage=sqlite',
                '--manager',
                '--hash-scheme=bcrypt',
            ],
        );
    }

    private function bindResultCode(string $password): int
    {
        $client = $this->buildClient('tcp');

        try {
            $client->bind(
                self::USER_DN,
                $password,
            );
        } catch (BindException $e) {
            return $e->getCode();
        } finally {
            $client->unbind();
        }

        return ResultCode::SUCCESS;
    }
}
