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
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\TestWorker;
use Throwable;

/**
 * A read-only replica mirroring a locally spawned provider over RFC 4533.
 */
abstract class SyncReplReplicaTestCase extends ServerTestCase
{
    public function setUp(): void
    {
        $this->setServerMode('ldap-replica');

        parent::setUp();
    }

    public function test_seeded_entries_replicate_to_the_replica(): void
    {
        self::assertNotNull($this->waitForReplica('cn=alice,ou=people,dc=foo,dc=bar'));
    }

    /**
     * Full refresh must ship both populations, or it would disagree with the incremental path.
     */
    public function test_seeded_subentries_replicate_to_the_replica(): void
    {
        self::assertNotNull($this->waitForReplica('cn=sync-policy,ou=people,dc=foo,dc=bar'));
    }

    public function test_an_add_on_the_provider_propagates_to_the_replica(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=dave,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'dave',
                    'sn' => 'Davis',
                ],
            ));
        });

        self::assertNotNull($this->waitForReplica('cn=dave,ou=people,dc=foo,dc=bar'));
    }

    public function test_a_delete_on_the_provider_propagates_to_the_replica(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=eve,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'eve',
                    'sn' => 'Evans',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=eve,ou=people,dc=foo,dc=bar'));

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->delete('cn=eve,ou=people,dc=foo,dc=bar');
        });
        self::assertNull($this->waitForReplicaGone('cn=eve,ou=people,dc=foo,dc=bar'));
    }

    /**
     * RFC 4533 §3.6 keys entries by entryUUID, so a move must relocate the replica's copy rather than add a second.
     */
    public function test_a_rename_on_the_provider_relocates_rather_than_duplicating(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=frank,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'frank',
                    'sn' => 'Franklin',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=frank,ou=people,dc=foo,dc=bar'));

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->rename(
                'cn=frank,ou=people,dc=foo,dc=bar',
                'cn=franklin',
            );
        });

        self::assertNotNull($this->waitForReplica('cn=franklin,ou=people,dc=foo,dc=bar'));
        self::assertNull(
            $this->waitForReplicaGone('cn=frank,ou=people,dc=foo,dc=bar'),
            'The replica must not keep the entry at the DN it moved from.',
        );
    }

    /**
     * A subtree move journals one record per relocated entry, so every descendant has to relocate too.
     */
    public function test_a_subtree_move_on_the_provider_relocates_every_descendant(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'ou=staff,dc=foo,dc=bar',
                [
                    'objectClass' => 'organizationalUnit',
                    'ou' => 'staff',
                ],
            ));
            $provider->create(Entry::fromArray(
                'cn=grace,ou=staff,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'grace',
                    'sn' => 'Hopper',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=grace,ou=staff,dc=foo,dc=bar'));

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->rename(
                'ou=staff,dc=foo,dc=bar',
                'ou=crew',
            );
        });

        self::assertNotNull($this->waitForReplica('cn=grace,ou=crew,dc=foo,dc=bar'));
        self::assertNull(
            $this->waitForReplicaGone('cn=grace,ou=staff,dc=foo,dc=bar'),
            'A descendant must not be left behind beneath the old base.',
        );
        self::assertNull(
            $this->waitForReplicaGone('ou=staff,dc=foo,dc=bar'),
            'The moved base must not be left behind either.',
        );
    }

    /**
     * RFC 4533 §4.1 wants a delete when a move takes an entry out of the content the consumer asked for.
     */
    public function test_a_move_out_of_the_replicated_scope_deletes_from_the_replica(): void
    {
        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->create(Entry::fromArray(
                'cn=heidi,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'heidi',
                    'sn' => 'Lamarr',
                ],
            ));
        });
        self::assertNotNull($this->waitForReplica('cn=heidi,ou=people,dc=foo,dc=bar'));

        $this->writeToProvider(static function (LdapClient $provider): void {
            $provider->move(
                'cn=heidi,ou=people,dc=foo,dc=bar',
                'dc=other,dc=test',
            );
        });

        self::assertNull(
            $this->waitForReplicaGone('cn=heidi,ou=people,dc=foo,dc=bar'),
            'An entry that left the replicated content must not linger on the replica.',
        );
    }

    public function test_a_client_write_to_the_replica_is_referred_to_the_provider(): void
    {
        self::assertNotNull($this->waitForReplica('cn=alice,ou=people,dc=foo,dc=bar'));

        $client = $this->buildClient('tcp');
        $client->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $this->expectException(ReferralException::class);
            $client->create(Entry::fromArray(
                'cn=nope,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'nope',
                    'sn' => 'Nope',
                ],
            ));
        } finally {
            $client->unbind();
        }
    }

    /**
     * The URL is generated on one side and parsed on the other, so only a round trip proves either.
     */
    public function test_the_referral_url_survives_the_round_trip_to_the_client(): void
    {
        self::assertNotNull($this->waitForReplica('cn=alice,ou=people,dc=foo,dc=bar'));

        $client = $this->buildClient('tcp');
        $client->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $client->create(Entry::fromArray(
                'cn=nope,ou=people,dc=foo,dc=bar',
                [
                    'objectClass' => 'inetOrgPerson',
                    'cn' => 'nope',
                    'sn' => 'Nope',
                ],
            ));

            self::fail('The write should have been referred to the provider.');
        } catch (ReferralException $e) {
            $referrals = $e->getReferrals();

            self::assertCount(
                1,
                $referrals,
            );
            self::assertSame(
                sprintf(
                    'ldap://127.0.0.1:%d/',
                    TestWorker::port(TestWorker::OFFSET_PROVIDER),
                ),
                $referrals[0]->toString(),
            );
            self::assertSame(
                '127.0.0.1',
                $referrals[0]->getHost(),
            );
            self::assertSame(
                TestWorker::port(TestWorker::OFFSET_PROVIDER),
                $referrals[0]->getPort(),
            );
            self::assertFalse($referrals[0]->getUseSsl());
        } finally {
            $client->unbind();
        }
    }

    public function test_a_password_modify_on_the_replica_is_referred_to_the_provider(): void
    {
        $target = 'cn=user,dc=foo,dc=bar';
        self::assertNotNull($this->waitForReplica($target));

        $client = $this->buildClient('tcp');
        $client->bind(
            $target,
            '12345',
        );

        try {
            $this->expectException(ReferralException::class);
            $client->sendAndReceive(Operations::passwordModify(
                $target,
                '12345',
                'localonly',
            ));
        } finally {
            $client->unbind();
        }
    }

    public function test_repeated_failed_binds_lock_the_account_locally_on_the_replica(): void
    {
        $lockme = 'cn=lockme,ou=people,dc=foo,dc=bar';
        self::assertNotNull($this->waitForReplica($lockme));

        // The correct password works before any failures.
        $this->assertBind(
            $lockme,
            '12345',
            true,
        );

        // Two failed binds, each on a separate connection, reach pwdMaxFailure and lock locally.
        $this->assertBind(
            $lockme,
            'wrong',
            false,
        );
        $this->assertBind(
            $lockme,
            'wrong',
            false,
        );

        // The correct password is now rejected: the replica enforces its local lock across connections.
        $this->assertBind(
            $lockme,
            '12345',
            false,
        );
    }

    private function assertBind(
        string $dn,
        string $password,
        bool $shouldSucceed,
    ): void {
        $client = $this->buildClient('tcp');

        try {
            $client->bind(
                $dn,
                $password,
            );
            self::assertTrue(
                $shouldSucceed,
                "Expected the bind for {$dn} to fail.",
            );
        } catch (BindException $e) {
            self::assertFalse(
                $shouldSucceed,
                "Expected the bind for {$dn} to succeed: {$e->getMessage()}.",
            );
        } finally {
            try {
                $client->unbind();
            } catch (Throwable) {
                // The connection may already be gone after a failed bind.
            }
        }
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

    private function waitForReplicaGone(
        string $dn,
        float $timeoutSeconds = 15.0,
    ): ?Entry {
        $deadline = microtime(true) + $timeoutSeconds;

        do {
            $entry = $this->tryReadFromReplica($dn);

            if ($entry === null) {
                return null;
            }

            usleep(100_000);
        } while (microtime(true) < $deadline);

        return $entry;
    }

    private function tryReadFromReplica(string $dn): ?Entry
    {
        try {
            $client = $this->buildClient('tcp');
            $client->bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            );
            $entry = $client->read($dn);
            $client->unbind();

            return $entry;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * @param callable(LdapClient): void $write
     */
    private function writeToProvider(callable $write): void
    {
        $provider = $this->getClient(
            (new ClientOptions())
                ->setPort(TestWorker::port(TestWorker::OFFSET_PROVIDER))
                ->setServers(['127.0.0.1'])
                ->setSslValidateCert(false),
        );

        try {
            $provider->bind(
                'cn=admin,dc=foo,dc=bar',
                '12345',
            );
            $write($provider);
        } finally {
            $provider->unbind();
        }
    }
}
