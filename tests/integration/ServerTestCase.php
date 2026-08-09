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
use Tests\Support\FreeDSx\Ldap\TestWorker;

class ServerTestCase extends LdapTestCase
{
    private const SERVER_MAX_WAIT_SECONDS = 10;

    private const SERVER_POLL_INTERVAL_US = 15_000; // 15ms

    /**
     * Caps the SIGTERM grace period so a lingering client connection can't stall teardown for Symfony's default 10s.
     */
    private const SERVER_STOP_TIMEOUT_SECONDS = 0.5;

    /**
     * Shared server process — started once per test class via setUpBeforeClass.
     */
    private static ?Process $sharedProcess = null;

    /**
     * Stored so the shared server can be restarted after a test that stops it.
     */
    private static string $sharedMode = 'ldap-server';

    private static string $sharedTransport = 'tcp';

    /**
     * @var list<string>
     */
    private static array $sharedExtraArgs = [];

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

    private string $serverMode = 'ldap-server';

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
        // Ahead of the parent, which closes the socket. Unbinding afterwards would only reconnect to send it.
        try {
            $this->client?->unbind();
        } catch (\Throwable) {
            // Server may have already closed; ignore unbind failures during teardown.
        }
        $this->client = null;

        parent::tearDown();

        if ($this->overrideProcess !== null) {
            self::stopProcessTree($this->overrideProcess);
            $this->overrideProcess = null;
        }

        if ($this->needsSharedRestart) {
            self::launchSharedProcess(
                self::$sharedMode,
                self::$sharedTransport,
                self::$sharedExtraArgs,
            );
            $this->needsSharedRestart = false;
        }
    }

    /**
     * Shared-server lifecycle — called from setUpBeforeClass / tearDownAfterClass
     */
    /**
     * @param list<string> $extraArgs
     */
    protected static function initSharedServer(
        string $mode,
        string $transport,
        array $extraArgs = [],
    ): void {
        self::$sharedMode = $mode;
        self::$sharedTransport = $transport;
        self::$sharedExtraArgs = $extraArgs;

        self::launchSharedProcess($mode, $transport, $extraArgs);
    }

    protected static function tearDownSharedServer(): void
    {
        if (self::$sharedProcess !== null) {
            self::stopProcessTree(self::$sharedProcess);
            self::$sharedProcess = null;
        }
    }

    /**
     * Per-test server override. For tests that require a different config.
     *
     * Anything already listening is stopped first, since only one server can hold the port.
     *
     * @param list<string> $extraArgs
     */
    protected function createServerProcess(
        string $transport,
        array $extraArgs = [],
    ): void {
        $this->stopServer();

        $processArgs = [
            'php',
            '-dpcov.enabled=0',
            __DIR__ . '/../bin/' . $this->serverMode . '.php',
            '--transport=' . $transport,
            ...$extraArgs,
        ];

        $process = new Process($processArgs);
        $process->start();
        self::waitForProcess($process, 'server starting...');

        $this->overrideProcess = $process;
        $this->client = $this->buildClient($transport);
    }

    protected function stopServer(): void
    {
        try {
            $this->client?->unbind();
        } catch (\Throwable) {
            // Connection may already be closed; ignore unbind failures.
        }
        $this->client = null;

        if ($this->overrideProcess !== null) {
            self::stopProcessTree($this->overrideProcess);
            $this->overrideProcess = null;
        } elseif (self::$sharedProcess !== null) {
            self::stopProcessTree(self::$sharedProcess);
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

    protected function sendServerSignal(int $signal): void
    {
        $process = $this->overrideProcess ?? self::$sharedProcess
            ?? throw new RuntimeException('No server process is running.');

        $pid = $process->getPid();

        if ($pid === null) {
            throw new RuntimeException('The server process has no PID.');
        }

        posix_kill(
            $pid,
            $signal,
        );
    }

    protected function isServerRunning(): bool
    {
        $process = $this->overrideProcess ?? self::$sharedProcess;

        return $process?->isRunning() ?? false;
    }

    /**
     * Binds as an ordinary identity with no administrative rights.
     */
    protected function authenticateUser(): void
    {
        $this->ldapClient()->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
    }

    /**
     * Binds as an identity the harness configures as an administrator, for tests that write.
     */
    protected function authenticateAdmin(): void
    {
        $this->ldapClient()->bind(
            'cn=admin,dc=foo,dc=bar',
            '12345',
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

    protected function buildClient(string $transport): LdapClient
    {
        $useSsl = false;
        $servers = '127.0.0.1';

        if ($transport === 'ssl') {
            $transport = 'tcp';
            $useSsl = true;
        }
        if ($transport === 'unix') {
            $servers = TestWorker::path('ldap.socket');
        }

        return $this->getClient(
            $this->makeOptions()
                ->setPort(TestWorker::port())
                ->setTransport($transport)
                ->setServers((array) $servers)
                ->setSslValidateCert(false)
                ->setUseSsl($useSsl),
        );
    }

    /**
     * @param list<string> $extraArgs
     */
    private static function launchSharedProcess(
        string $mode,
        string $transport,
        array $extraArgs,
    ): void {
        $processArgs = [
            'php',
            '-dpcov.enabled=0',
            __DIR__ . '/../bin/' . $mode . '.php',
            '--transport=' . $transport,
            ...$extraArgs,
        ];

        $process = new Process($processArgs);
        $process->start();
        self::waitForProcess($process, 'server starting...');

        self::$sharedProcess = $process;
    }

    /**
     * Stops a process and SIGKILLs any descendants, since nested children (provider/upstream) are only cleaned up via
     * the parent's shutdown function, which does not run on a signal kill.
     */
    private static function stopProcessTree(Process $process): void
    {
        $pid = $process->getPid();
        $descendants = $pid !== null
            ? self::descendantPids($pid)
            : [];

        $process->stop(self::SERVER_STOP_TIMEOUT_SECONDS);

        foreach ($descendants as $descendant) {
            if (@posix_kill($descendant, 0)) {
                @posix_kill($descendant, SIGKILL);
            }
        }
    }

    /**
     * Walks the process tree below a pid (via pgrep -P) so descendants can be reaped before they are orphaned.
     *
     * @return list<int>
     */
    private static function descendantPids(int $pid): array
    {
        $found = [];
        $queue = [$pid];

        while ($queue !== []) {
            $current = array_shift($queue);
            $children = [];
            exec(
                sprintf('pgrep -P %d 2>/dev/null', $current),
                $children,
            );

            foreach ($children as $child) {
                $childPid = (int) trim($child);

                if ($childPid > 0) {
                    $found[] = $childPid;
                    $queue[] = $childPid;
                }
            }
        }

        return $found;
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
            PHP_EOL . $process->getErrorOutput(),
        ));
    }
}
