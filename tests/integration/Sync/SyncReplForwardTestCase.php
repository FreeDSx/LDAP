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

namespace Tests\Integration\FreeDSx\Ldap\Sync;

use DateTimeImmutable;
use DateTimeZone;
use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ForwardPasswordPolicyStateRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Utility\Uuid;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\LdapServerCommand;
use Tests\Support\FreeDSx\Ldap\TestWorker;
use Throwable;

/**
 * A read-only replica that forwards its ppolicy bind-state to the provider it mirrors over RFC 4533.
 */
abstract class SyncReplForwardTestCase extends ServerTestCase
{
    private const PWD_LOCKED_TIME = 'pwdAccountLockedTime';

    private const PWD_FAILURE_TIME = 'pwdFailureTime';

    /**
     * What the engine keeps when the policy names no maximum of its own.
     */
    private const RETAINED_FAILURES = 16;

    public function setUp(): void
    {
        $this->setServerMode('ldap-replica');

        parent::setUp();
    }

    public function test_replica_bind_failures_roll_up_to_a_global_lock_on_the_provider(): void
    {
        $dn = 'cn=lockme,ou=people,dc=foo,dc=bar';
        self::assertNotNull($this->waitForReplica($dn));
        self::assertFalse($this->providerHasLock($dn));

        // Two failed binds on the replica reach the local threshold and queue the failures for forward.
        $this->tryReplicaBind($dn, 'wrong');
        $this->tryReplicaBind($dn, 'wrong');

        // The forwarded failures roll up on the provider and lock the account globally.
        self::assertTrue(
            $this->pollUntil(fn(): bool => $this->providerHasLock($dn)),
            'The replica failures should forward and lock the account on the provider.',
        );
    }

    public function test_a_password_reset_on_the_provider_retires_the_replica_local_lock(): void
    {
        $dn = 'cn=resetme,ou=people,dc=foo,dc=bar';
        self::assertNotNull($this->waitForReplica($dn));

        $this->tryReplicaBind($dn, 'wrong');
        $this->tryReplicaBind($dn, 'wrong');

        // Let the forward fully apply so the reset below does not race an in-flight forward.
        self::assertTrue(
            $this->pollUntil(fn(): bool => $this->providerHasLock($dn)),
            'The account should first lock on the provider via forward.',
        );

        // An admin reset on the provider advances pwdChangedTime and clears the lockout.
        $this->resetPasswordOnProvider($dn, 'newpass');
        self::assertTrue(
            $this->pollUntil(fn(): bool => !$this->providerHasLock($dn)),
            'The provider reset should clear the lock.',
        );

        // The reset replicates back; the replica supersedes its local lock and accepts the new password.
        self::assertTrue(
            $this->pollUntil(fn(): bool => $this->replicaBindSucceeds($dn, 'newpass')),
            'The replica should retire its local lock once the reset replicates.',
        );
    }

    public function test_a_deleted_accounts_failures_are_not_forwarded_to_an_account_recreated_at_its_dn(): void
    {
        $dn = 'cn=recreated,ou=people,dc=foo,dc=bar';

        $this->writeToProvider(static function (LdapClient $provider) use ($dn): void {
            $provider->create(Entry::fromArray(
                $dn,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'recreated',
                    'sn' => 'Original',
                    'userPassword' => 'oldpass',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica($dn));
        $this->tryReplicaBind($dn, 'wrong');

        $this->writeToProvider(static function (LdapClient $provider) use ($dn): void {
            $provider->delete($dn);
            $provider->create(Entry::fromArray(
                $dn,
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'recreated',
                    'sn' => 'Recreated',
                    'userPassword' => 'newpass',
                ],
            ));
        });
        self::assertTrue(
            $this->pollUntil(fn(): bool => $this->tryReadFromReplica($dn)?->get('sn')?->firstValue() === 'Recreated'),
            'The recreated account should replicate.',
        );
        $this->tryReplicaBind($dn, 'wrong');

        // Once the recreated account's own failure is forwarded, it is the only one the provider holds for it.
        self::assertTrue(
            $this->pollUntil(fn(): bool => $this->failureTimesOnProvider($dn) !== []),
            'The recreated account\'s own failure should forward.',
        );
        self::assertCount(
            1,
            $this->failureTimesOnProvider($dn),
        );
        self::assertFalse($this->providerHasLock($dn));
    }

    public function test_a_forward_naming_an_unknown_uuid_applies_nowhere(): void
    {
        $before = $this->lockedDnsOnProvider();

        $client = $this->providerClient();

        try {
            $client->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
            $client->sendAndReceive(new ForwardPasswordPolicyStateRequest(
                Uuid::v4(),
                [
                    new DateTimeImmutable('-2 seconds', new DateTimeZone('UTC')),
                    new DateTimeImmutable('-1 second', new DateTimeZone('UTC')),
                ],
            ));
        } finally {
            $this->quietUnbind($client);
        }

        self::assertSame(
            $before,
            $this->lockedDnsOnProvider(),
            'A forward for a UUID the primary does not hold must lock nothing.',
        );
    }

    public function test_a_forward_beyond_the_record_limit_stores_only_what_is_retained(): void
    {
        $dn = 'cn=carol,ou=people,dc=foo,dc=bar';
        $uuid = $this->uuidOnProvider($dn);
        self::assertNotNull($uuid);

        $times = [];
        for ($i = 40; $i > 0; $i--) {
            $times[] = new DateTimeImmutable(
                "-{$i} seconds",
                new DateTimeZone('UTC'),
            );
        }

        $client = $this->providerClient();

        try {
            $client->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
            $client->sendAndReceive(new ForwardPasswordPolicyStateRequest(
                $uuid,
                $times,
            ));
        } finally {
            $this->quietUnbind($client);
        }

        // The policy names no maximum, so retention falls to the engine's own bound.
        self::assertCount(
            self::RETAINED_FAILURES,
            $this->failureTimesOnProvider($dn),
        );
    }

    public function test_a_forward_with_a_malformed_uuid_is_refused(): void
    {
        $client = $this->providerClient();

        try {
            $client->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );

            $this->expectException(OperationException::class);
            $this->expectExceptionCode(ResultCode::PROTOCOL_ERROR);

            $client->sendAndReceive(
                (new ExtendedRequest(ExtendedRequest::OID_PPOLICY_STATE_FORWARD))
                    ->setValue(Asn1::sequence(
                        Asn1::octetString('not-a-uuid'),
                        Asn1::setOf(),
                    )),
            );
        } finally {
            $this->quietUnbind($client);
        }
    }

    /**
     * @return list<string>
     */
    private function lockedDnsOnProvider(): array
    {
        $manager = $this->providerClient();

        try {
            $manager->bind(
                LdapServerCommand::MANAGER_DN,
                LdapServerCommand::MANAGER_PASSWORD,
            );
            $entries = $manager->search(Operations::search(
                Filters::present(self::PWD_LOCKED_TIME),
                '1.1',
            )->base('ou=people,dc=foo,dc=bar'));

            $dns = [];
            foreach ($entries as $entry) {
                $dns[] = $entry->getDn()->toString();
            }
            sort($dns);

            return $dns;
        } finally {
            $this->quietUnbind($manager);
        }
    }

    private function uuidOnProvider(string $dn): ?string
    {
        $manager = $this->providerClient();

        try {
            $manager->bind(
                LdapServerCommand::MANAGER_DN,
                LdapServerCommand::MANAGER_PASSWORD,
            );

            return $manager->read(
                $dn,
                ['entryUUID'],
            )?->get('entryUUID')?->firstValue();
        } finally {
            $this->quietUnbind($manager);
        }
    }

    /**
     * @return list<string>
     */
    private function failureTimesOnProvider(string $dn): array
    {
        $manager = $this->providerClient();

        try {
            $manager->bind(
                LdapServerCommand::MANAGER_DN,
                LdapServerCommand::MANAGER_PASSWORD,
            );
            $entry = $manager->read(
                $dn,
                [self::PWD_FAILURE_TIME],
            );

            return array_values($entry?->get(self::PWD_FAILURE_TIME)?->getValues() ?? []);
        } finally {
            $this->quietUnbind($manager);
        }
    }

    private function providerHasLock(string $dn): bool
    {
        $manager = $this->providerClient();

        try {
            $manager->bind(
                LdapServerCommand::MANAGER_DN,
                LdapServerCommand::MANAGER_PASSWORD,
            );
            $entry = $manager->read(
                $dn,
                [self::PWD_LOCKED_TIME],
            );

            return $entry?->get(self::PWD_LOCKED_TIME) !== null;
        } catch (Throwable) {
            return false;
        } finally {
            $this->quietUnbind($manager);
        }
    }

    private function resetPasswordOnProvider(
        string $dn,
        string $newPassword,
    ): void {
        $manager = $this->providerClient();

        try {
            $manager->bind(
                LdapServerCommand::MANAGER_DN,
                LdapServerCommand::MANAGER_PASSWORD,
            );
            $manager->sendAndReceive(new PasswordModifyRequest(
                $dn,
                null,
                $newPassword,
            ));
        } finally {
            $this->quietUnbind($manager);
        }
    }

    private function replicaBindSucceeds(
        string $dn,
        string $password,
    ): bool {
        $client = $this->buildClient('tcp');

        try {
            $client->bind(
                $dn,
                $password,
            );

            return true;
        } catch (BindException) {
            return false;
        } finally {
            $this->quietUnbind($client);
        }
    }

    private function tryReplicaBind(
        string $dn,
        string $password,
    ): void {
        $this->replicaBindSucceeds($dn, $password);
    }

    private function waitForReplica(
        string $dn,
        float $timeoutSeconds = 15.0,
    ): ?Entry {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            $entry = $this->tryReadFromReplica($dn);

            if ($entry !== null) {
                return $entry;
            }

            usleep(100_000);
        } while (microtime(true) < $deadline);

        return null;
    }

    private function tryReadFromReplica(string $dn): ?Entry
    {
        $client = $this->buildClient('tcp');

        try {
            $client->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );

            return $client->read($dn);
        } catch (Throwable) {
            return null;
        } finally {
            $this->quietUnbind($client);
        }
    }

    /**
     * @param callable(): bool $condition
     */
    private function pollUntil(
        callable $condition,
        float $timeoutSeconds = 25.0,
    ): bool {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            if ($condition()) {
                return true;
            }

            usleep(200_000);
        } while (microtime(true) < $deadline);

        return false;
    }

    /**
     * @param callable(LdapClient): void $write
     */
    private function writeToProvider(callable $write): void
    {
        $provider = $this->providerClient();

        try {
            $provider->bind(
                'cn=admin,dc=foo,dc=bar',
                '12345',
            );
            $write($provider);
        } finally {
            $this->quietUnbind($provider);
        }
    }

    private function providerClient(): LdapClient
    {
        return $this->getClient(
            (new ClientOptions())
                ->setPort(TestWorker::port(TestWorker::OFFSET_PROVIDER))
                ->setServers(['127.0.0.1'])
                ->setSslValidateCert(false),
        );
    }

    private function quietUnbind(LdapClient $client): void
    {
        try {
            $client->unbind();
        } catch (Throwable) {
            // The connection may already be gone after a failed or locked bind.
        }
    }
}
