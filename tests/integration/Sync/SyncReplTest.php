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

use FreeDSx\Ldap\Exception\CancelRequestException;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;
use Symfony\Component\Process\Process;
use Tests\Integration\FreeDSx\Ldap\LdapTestCase;

class SyncReplTest extends LdapTestCase
{
    private ?Process $syncWriteProcess = null;

    protected function setUp(): void
    {
        parent::setUp();

        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('SyncRepl tests require a native Linux slapd instance.');
        }

        // OpenLDAP ITS#6138: a cancel during SyncRepl can crash slapd. The Docker container is
        // configured with restart: on-failure, so we wait here for it to recover before each test.
        $this->waitForServer();
    }

    private ?string $syncSignalFile = null;

    public function tearDown(): void
    {
        $this->syncWriteProcess?->stop();
        $this->syncWriteProcess = null;

        if ($this->syncSignalFile !== null && file_exists($this->syncSignalFile)) {
            unlink($this->syncSignalFile);
            $this->syncSignalFile = null;
        }
    }

    public function testItCanPerformPollingSync(): void
    {
        $entries = [];

        $client = $this->getClient();
        $this->bindClient($client);

        $client
            ->syncRepl(Filters::equal('objectClass', 'organizationalUnit'))
            ->poll(function (SyncEntryResult $result) use (&$entries): void {
                $entries[] = $result;
            });

        $this->assertGreaterThan(0, count($entries));
    }

    public function testItCanCancelTheSync(): void
    {
        $client = $this->getClient(
            $this->makeOptions()->setTimeoutRead(180)
        );
        $this->bindClient($client);

        $count = 0;
        $client
            ->syncRepl()
            ->listen(function () use (&$count): void {
                if ($count === 10) {
                    throw new CancelRequestException();
                }
                $count++;
            });

        $this->assertSame(
            10,
            $count,
            'It stopped on the 10th result.'
        );
    }

    public function testListenObservesBothRefreshAndPersistPhases(): void
    {
        $this->syncSignalFile = tempnam(sys_get_temp_dir(), 'ldap_sync_test_');
        unlink($this->syncSignalFile);

        $process = $this->syncWriteProcess();
        $process->start();

        $state = new SyncListenState();

        $listenClient = $this->getClient(
            $this->makeOptions()->setTimeoutRead(180)
        );
        $this->bindClient($listenClient);

        $listenClient->syncRepl()
            ->listen(function (SyncEntryResult $result, Session $session) use ($state): void {
                // Signal the write process on the first entry received (we are in the refresh phase).
                // OpenLDAP queues writes that happen during refresh and delivers them in the persist phase.
                if (!$state->signaled) {
                    touch((string) $this->syncSignalFile);
                    $state->signaled = true;
                }

                if (!$session->isRefreshComplete()) {
                    $state->seenRefreshPhase = true;
                    return;
                }

                // we are in the persist phase.
                $state->seenPersistPhase = true;

                throw new CancelRequestException();
            });

        $process->wait();

        $this->assertTrue(
            $process->isSuccessful(),
            'The sync write should run successfully. Instead received: '. $process->getErrorOutput(),
        );
        $this->assertTrue(
            $state->seenRefreshPhase,
            'Entries were received during the refresh phase.'
        );
        $this->assertTrue(
            $state->seenPersistPhase,
            'An entry was received during the persist phase.'
        );
    }

    private function syncWriteProcess(): Process
    {
        $process = new Process([
            'php',
            __DIR__ . '/../../bin/ldapsyncwrite.php',
            $this->syncSignalFile,
        ]);
        $process->setTimeout(60);
        $this->syncWriteProcess = $process;

        return $process;
    }

    private function waitForServer(): void
    {
        $server = (string) (getenv('LDAP_SERVER') ?: 'localhost');
        $port = (int) (getenv('LDAP_PORT') ?: 389);

        for ($i = 0; $i < 30; $i++) {
            $connection = @fsockopen(
                $server,
                $port,
                $errno,
                $errstr,
                1.0
            );

            if ($connection !== false) {
                fclose($connection);

                return;
            }

            sleep(1);
        }

        $this->fail(sprintf(
            'LDAP server at %s:%d did not become available within %d seconds.',
            $server,
            $port,
            30,
        ));
    }
}
