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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Auth\ManagerIdentity;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\Config\PasswordHashing;
use FreeDSx\Ldap\Server\Config\PasswordHashLimits;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use Tests\Support\FreeDSx\Ldap\Storage\EntryFixture;

/**
 * In-process integration of the stored-hash work limits, from the password configuration through to a bind.
 */
final class PasswordHashLimitsTest extends TestCase
{
    use ServerContainerTrait;

    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private const PASSWORD = 'secret';

    public function test_a_bind_against_a_stored_hash_within_the_limits_succeeds(): void
    {
        $token = $this->authenticatorWith(new PasswordHashLimits(bcryptCost: 5))->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );

        self::assertSame(
            self::USER_DN,
            $token->getResolvedDn()->toString(),
        );
    }

    public function test_a_bind_against_a_stored_hash_over_the_limits_fails_as_invalid_credentials(): void
    {
        $authenticator = $this->authenticatorWith(new PasswordHashLimits(bcryptCost: 4));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $authenticator->authenticate(
            self::USER_DN,
            self::PASSWORD,
        );
    }

    public function test_a_bind_against_a_stored_hash_over_the_limits_is_logged_naming_the_entry(): void
    {
        $logger = new RecordingLogger();
        $authenticator = $this->authenticatorWith(
            new PasswordHashLimits(bcryptCost: 4),
            $logger,
        );

        try {
            $authenticator->authenticate(
                self::USER_DN,
                self::PASSWORD,
            );
            self::fail('The bind should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_CREDENTIALS,
                $e->getCode(),
            );
        }

        $targets = [];
        foreach ($logger->records as $record) {
            if (($record['context'][EventContext::EVENT] ?? null) === ServerEvent::PasswordHashOverLimits->value) {
                $targets[] = $record['context'][EventContext::TARGET] ?? null;
            }
        }
        self::assertSame(
            [[EventContext::DN => self::USER_DN]],
            $targets,
        );
    }

    public function test_a_manager_password_hash_over_the_limits_is_refused_at_startup(): void
    {
        $container = $this->containerFor(
            EntryFixture::inMemoryStorage(),
            TestServerOptions::defaults()->setManager(new ManagerIdentity(
                new Dn('cn=manager'),
                '{CRYPT}$6$rounds=2000000$saltsaltsalt$hash',
            )),
        );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            'The manager password can never be verified. The "{CRYPT}" password hash asks for more work than the '
            . 'configured limits allow.',
        );

        $container->get(ServerProtocolFactoryInterface::class);
    }

    public function test_the_server_verifies_its_own_hashes_when_its_hashing_asks_for_more_than_the_limits(): void
    {
        $hashService = $this->fromContainer(
            PasswordHashService::class,
            options: TestServerOptions::defaults()->setPasswordConfig(new PasswordConfig(
                new PasswordHashLimits(
                    argon2Memory: 8,
                    argon2MemoryPasses: 8,
                ),
                hashing: PasswordHashing::argon2id(
                    memoryKiB: 16,
                    passes: 1,
                ),
            )),
        );

        self::assertTrue($hashService->verify(
            self::PASSWORD,
            $hashService->hash(self::PASSWORD),
        ));
    }

    /**
     * The user holds a cost 5 bcrypt hash, and the server hashes with SSHA so its own cost raises no bcrypt limit.
     */
    private function authenticatorWith(
        PasswordHashLimits $limits,
        ?LoggerInterface $logger = null,
    ): PasswordAuthenticatableInterface {
        return $this->containerFor(
            EntryFixture::inMemoryStorage(
                new Entry(
                    new Dn('dc=foo,dc=bar'),
                    new Attribute('objectClass', 'domain'),
                    new Attribute('dc', 'foo'),
                ),
                new Entry(
                    new Dn(self::USER_DN),
                    new Attribute('objectClass', 'person'),
                    new Attribute('cn', 'user'),
                    new Attribute('sn', 'user'),
                    new Attribute(
                        'userPassword',
                        '{BCRYPT}' . password_hash(
                            self::PASSWORD,
                            PASSWORD_BCRYPT,
                            ['cost' => 5],
                        ),
                    ),
                ),
            ),
            $this->optionsWith(
                $limits,
                $logger,
            ),
        )->get(PasswordAuthenticatableInterface::class);
    }

    private function optionsWith(
        PasswordHashLimits $limits,
        ?LoggerInterface $logger,
    ): ServerOptions {
        return TestServerOptions::defaults()
            ->setLogger($logger)
            ->setPasswordConfig(
                (new PasswordConfig())
                    ->setHashLimits($limits)
                    ->setHashing(PasswordHashing::ssha()),
            );
    }
}
