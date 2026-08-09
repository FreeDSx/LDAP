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

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
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

        // The replica enforces its own lock across connections before anything replicates back.
        self::assertFalse($this->replicaBindSucceeds($dn, '12345'));

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
