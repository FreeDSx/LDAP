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

use Exception;
use FreeDSx\Ldap\LdapClient;
use RuntimeException;
use Symfony\Component\Process\Process;

class ServerTestCase extends LdapTestCase
{
    private const SERVER_MAX_WAIT_SECONDS = 10;

    private const SERVER_POLL_INTERVAL_US = 15_000; // 15ms

    private const SERVER_TCP_PORT = 10389;

    /**
     * Shared server process — started once per test class via setUpBeforeClass.
     */
    private static ?Process $sharedProcess = null;

    /**
     * Stored so the shared server can be restarted after a test that stops it.
     */
    private static string $sharedMode = 'ldapserver';

    private static string $sharedTransport = 'tcp';

    private static ?string $sharedHandler = null;

    /**
     * Per-test client — a fresh connection to the shared server for each test.
     */
    private ?LdapClient $client = null;

    /**
     * Set when a test spins up its own server (paging, ssl, unix).
     */
    private ?Process $overrideProcess = null;

    /**
     * Set when stopServer() halts the shared process so tearDown can restore it.
     */
    private bool $needsSharedRestart = false;

    private string $serverMode = 'ldapserver';

    public function setUp(): void
    {
        parent::setUp();

        if (!extension_loaded('pcntl')) {
            $this->markTestSkipped('The PCNTL extension is required to run the built-in LDAP server.');
        }

        if (self::$sharedProcess !== null) {
            // Clear any leftover output from the previous test before creating
            // the client so waitForServerOutput() never sees stale markers.
            self::$sharedProcess->clearOutput();
            $this->client = $this->buildClient(self::$sharedTransport);
        }
    }

    public function tearDown(): void
    {
        parent::tearDown();

        $this->client?->unbind();
        $this->client = null;

        if ($this->overrideProcess !== null) {
            $this->overrideProcess->stop();
            $this->overrideProcess = null;
        }

        if ($this->needsSharedRestart) {
            self::launchSharedProcess(
                self::$sharedMode,
                self::$sharedTransport,
                self::$sharedHandler,
            );
            $this->needsSharedRestart = false;
        }
    }

    /**
     * Shared-server lifecycle — called from setUpBeforeClass / tearDownAfterClass
     */
    protected static function initSharedServer(
        string $mode,
        string $transport,
        ?string $handler = null,
    ): void {
        self::$sharedMode = $mode;
        self::$sharedTransport = $transport;
        self::$sharedHandler = $handler;

        self::launchSharedProcess($mode, $transport, $handler);
    }

    protected static function tearDownSharedServer(): void
    {
        self::$sharedProcess?->stop();
        self::$sharedProcess = null;
    }

    /**
     * Per-test server override. For tests that require a different config
     */
    protected function createServerProcess(
        string $transport,
        ?string $handler = null,
    ): void {
        $processArgs = [
            'php',
            __DIR__ . '/../bin/' . $this->serverMode . '.php',
            $transport,
        ];

        if ($handler !== null) {
            $processArgs[] = $handler;
        }

        $process = new Process($processArgs);
        $process->start();
        self::waitForProcess($process, 'server starting...');

        if ($transport !== 'unix') {
            self::waitForPortOpen(self::SERVER_TCP_PORT);
        }

        $this->overrideProcess = $process;
        $this->client = $this->buildClient($transport);
    }

    protected function stopServer(): void
    {
        $this->client?->unbind();
        $this->client = null;

        if ($this->overrideProcess !== null) {
            $this->overrideProcess->stop();
            $this->overrideProcess = null;
        } elseif (self::$sharedProcess !== null) {
            self::$sharedProcess->stop();
            self::$sharedProcess = null;
            $this->needsSharedRestart = true;
        }
    }

    protected function waitForServerOutput(string $marker): string
    {
        $process = $this->overrideProcess ?? self::$sharedProcess
            ?? throw new RuntimeException('No server process is running.');

        return self::waitForProcess(
            $process,
            $marker,
        );
    }

    protected function authenticate(): void
    {
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345'
        );
    }

    protected function setServerMode(string $mode): void
    {
        $this->serverMode = $mode;
    }

    protected function ldapClient(): LdapClient
    {
        return $this->client ?? throw new RuntimeException('The test LDAP client is not set.');
    }

    private static function launchSharedProcess(
        string $mode,
        string $transport,
        ?string $handler,
    ): void {
        $processArgs = [
            'php',
            __DIR__ . '/../bin/' . $mode . '.php',
            $transport,
        ];

        if ($handler !== null) {
            $processArgs[] = $handler;
        }

        $process = new Process($processArgs);
        $process->start();
        self::waitForProcess($process, 'server starting...');

        if ($transport !== 'unix') {
            self::waitForPortOpen(self::SERVER_TCP_PORT);
        }

        self::$sharedProcess = $process;
    }

    /**
     * Probes localhost:$port until a TCP connection succeeds or the timeout
     * expires. Called after waitForProcess() because the server bootstrap
     * script echoes "server starting..." before the socket is bound, so the
     * process output marker alone is not sufficient to guarantee readiness.
     */
    private static function waitForPortOpen(int $port): void
    {
        $deadline = microtime(true) + self::SERVER_MAX_WAIT_SECONDS;

        while (microtime(true) < $deadline) {
            $socket = @fsockopen(
                '127.0.0.1',
                $port,
                $errno,
                $errstr,
                0.1
            );

            if ($socket !== false) {
                fclose($socket);
                usleep(100_000); // 100ms stabilization after successful probe

                return;
            }

            usleep(self::SERVER_POLL_INTERVAL_US);
        }

        throw new Exception(sprintf(
            'Port %d was not ready after %d seconds.',
            $port,
            self::SERVER_MAX_WAIT_SECONDS,
        ));
    }

    private function buildClient(string $transport): LdapClient
    {
        $useSsl = false;
        $servers = '127.0.0.1';

        if ($transport === 'ssl') {
            $transport = 'tcp';
            $useSsl = true;
        }
        if ($transport === 'unix') {
            $servers = sys_get_temp_dir() . '/ldap.socket';
        }

        return $this->getClient(
            $this->makeOptions()
                ->setPort(10389)
                ->setTransport($transport)
                ->setServers((array) $servers)
                ->setSslValidateCert(false)
                ->setUseSsl($useSsl)
        );
    }

    private static function waitForProcess(Process $process, string $marker): string
    {
        $deadline = microtime(true) + self::SERVER_MAX_WAIT_SECONDS;

        while ($process->isRunning()) {
            $output = $process->getOutput();
            $process->clearOutput();

            if (str_contains($output, $marker)) {
                return $output;
            }

            if (microtime(true) >= $deadline) {
                break;
            }

            usleep(self::SERVER_POLL_INTERVAL_US);
        }

        throw new Exception(sprintf(
            'The expected output (%s) was not received after %d seconds. Received: %s',
            $marker,
            self::SERVER_MAX_WAIT_SECONDS,
            PHP_EOL . $process->getErrorOutput()
        ));
    }
}
