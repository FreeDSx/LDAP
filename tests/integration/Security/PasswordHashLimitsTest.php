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
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\Config\PasswordHashLimits;
use FreeDSx\Ldap\Server\ServerProtocolFactoryInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
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

    /**
     * The user holds a cost 5 bcrypt hash, and the server hashes with SSHA so its own cost raises no bcrypt limit.
     */
    private function authenticatorWith(PasswordHashLimits $limits): PasswordAuthenticatableInterface
    {
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
            $this->optionsWith($limits),
        )->get(PasswordAuthenticatableInterface::class);
    }

    private function optionsWith(PasswordHashLimits $limits): ServerOptions
    {
        return TestServerOptions::defaults()->setPasswordConfig(
            (new PasswordConfig())
                ->setHashLimits($limits)
                ->setHashScheme(PasswordHashScheme::Ssha),
        );
    }
}
