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

namespace Tests\Integration\FreeDSx\Ldap\Runner;

use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use Tests\Integration\FreeDSx\Ldap\Runner\Concern\ConnectionTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Runner\Concern\ReloadTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Runner\Concern\RequestLimitsTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Runner\Concern\SessionEndingLimitTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Runner\Concern\TlsTestsTrait;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;
use Tests\Support\FreeDSx\Ldap\TestWorker;

use function extension_loaded;

/**
 * Behavior that runs against every server runner.
 */
abstract class ServerRunnerTestCase extends ServerTestCase
{
    use TlsTestsTrait;
    use RequestLimitsTestsTrait;
    use SessionEndingLimitTestsTrait;
    use ConnectionTestsTrait;
    use ReloadTestsTrait;
    use RawClientQueueTrait;

    /**
     * Enough files to start and serve a few clients, and far fewer than the clients a test opens.
     */
    protected const OPEN_FILE_LIMIT = 64;

    public static function setUpBeforeClass(): void
    {
        if (!static::isRunnerAvailable()) {
            return;
        }
        parent::setUpBeforeClass();

        static::initSharedServer(
            'ldap-server',
            'tcp',
            static::runnerArgs(),
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();
    }

    /**
     * Appends the runner selection to every server this suite starts, including the per-test ones.
     *
     * @param list<string> $extraArgs
     */
    protected function createServerProcess(
        string $transport,
        array $extraArgs = [],
        ?int $openFileLimit = null,
    ): void {
        parent::createServerProcess(
            $transport,
            [...$extraArgs, ...static::runnerArgs()],
            $openFileLimit,
        );
    }

    /**
     * Connects without binding, leaving each connection for the server to accept and hold.
     *
     * @return list<resource>
     */
    protected function openRawClients(int $count): array
    {
        $clients = [];
        for ($i = 0; $i < $count; $i++) {
            $client = @stream_socket_client(
                'tcp://127.0.0.1:' . TestWorker::port(),
                $errorNumber,
                $errorMessage,
                0.1,
            );
            if ($client !== false) {
                $clients[] = $client;
            }
        }

        return $clients;
    }

    /**
     * @param list<resource> $clients
     */
    protected function closeRawClients(array $clients): void
    {
        foreach ($clients as $client) {
            fclose($client);
        }
    }

    protected function reloadServer(): void
    {
        $this->sendServerSignal(SIGHUP);
        $this->waitForServerOutput('Server configuration reloaded');
    }

    protected function makeFlagFile(): string
    {
        $flagFile = sys_get_temp_dir() . '/freedsx_runner_reload_' . uniqid('', true);
        file_put_contents(
            $flagFile,
            '',
        );

        return $flagFile;
    }

    /**
     * Hook for subclasses to name the runner the server runs under.
     *
     * @return list<string>
     */
    protected static function runnerArgs(): array
    {
        return [];
    }

    /**
     * Whether this runner can run here, which the pcntl one cannot without process control.
     */
    protected static function isRunnerAvailable(): bool
    {
        return extension_loaded('pcntl')
            && extension_loaded('posix');
    }

    protected function bindsUser(LdapClient $client): bool
    {
        try {
            $client->sendAndReceive(Operations::bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            ));
        } catch (ConnectionException) {
            return false;
        }

        return true;
    }
}
