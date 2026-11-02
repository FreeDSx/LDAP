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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;

final class LdapStoredPasswordTest extends ServerTestCase
{
    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private const HASHED_SECRET = 'hashed-secret';

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();

        $this->createServerProcess(
            'tcp',
            ['--storage=sqlite'],
        );
    }

    public function test_a_user_cannot_set_a_pre_hashed_password_on_their_own_entry(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->replacePassword(self::preHashed());
    }

    public function test_a_user_can_set_a_cleartext_password_on_their_own_entry(): void
    {
        $this->authenticateUser();

        $this->replacePassword('new-secret');

        $this->assertBindsAsUser('new-secret');
    }

    public function test_an_administrator_can_set_a_pre_hashed_password(): void
    {
        $this->authenticateAdmin();

        $this->replacePassword(self::preHashed());

        $this->assertBindsAsUser(self::HASHED_SECRET);
    }

    #[DataProvider('overTheLimitsProvider')]
    public function test_a_pre_hashed_password_over_the_hash_limits_is_refused_even_from_an_administrator(
        string $password,
    ): void {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->replacePassword($password);
    }

    /**
     * @return Generator<string, array{string}>
     */
    public static function overTheLimitsProvider(): Generator
    {
        yield 'sha-crypt rounds' => [
            '{CRYPT}$6$rounds=2000000$saltsaltsalt$hash',
        ];
        yield 'sha-crypt rounds spelled with a plus sign' => [
            '{CRYPT}$6$rounds=+2000000$saltsaltsalt$hash',
        ];
        yield 'bcrypt with the 2x prefix' => [
            '{CRYPT}$2x$15$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234',
        ];
    }

    public function test_a_second_password_value_is_refused(): void
    {
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->replacePassword(
            'first-secret',
            'second-secret',
        );
    }

    public function test_the_schema_refuses_a_second_password_even_when_the_configuration_allows_two(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--storage=sqlite',
                '--max-password-values=2',
            ],
        );
        $this->authenticateAdmin();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->replacePassword(
            'first-secret',
            'second-secret',
        );
    }

    private function replacePassword(string ...$passwords): void
    {
        $this->ldapClient()->send(Operations::modify(
            self::USER_DN,
            Change::replace(
                'userPassword',
                ...$passwords,
            ),
        ));
    }

    private function assertBindsAsUser(string $password): void
    {
        $client = $this->buildClient('tcp');
        $result = $client->bind(
            self::USER_DN,
            $password,
        )->getResponse();
        $client->unbind();

        self::assertInstanceOf(
            LdapResult::class,
            $result,
        );
        self::assertSame(
            ResultCode::SUCCESS,
            $result->getResultCode(),
        );
    }

    private static function preHashed(): string
    {
        return '{SHA}' . base64_encode(sha1(
            self::HASHED_SECRET,
            true,
        ));
    }
}
