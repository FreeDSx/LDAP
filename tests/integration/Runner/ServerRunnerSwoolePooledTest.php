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

use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use Tests\Support\FreeDSx\Ldap\RequiresExtensionsTrait;

use function array_map;
use function exec;
use function extension_loaded;
use function file_put_contents;
use function posix_kill;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

/**
 * Runs the shared runner suite against the pooled Swoole runner.
 */
final class ServerRunnerSwoolePooledTest extends ServerRunnerTestCase
{
    use RequiresExtensionsTrait;

    public function testAWorkerRespawnedAfterAReloadServesNothingUntilItCanAdoptOne(): void
    {
        $this->requirePosix();
        $flagFile = sys_get_temp_dir() . '/freedsx_pool_reload_' . uniqid('', true);
        file_put_contents(
            $flagFile,
            '',
        );
        $this->createServerProcess(
            'tcp',
            ['--log', '--reload-flag-file=' . $flagFile],
        );

        try {
            file_put_contents(
                $flagFile,
                'allow-anonymous',
            );
            $this->signalEachWorker(
                SIGHUP,
                'Server configuration reloaded',
            );

            file_put_contents(
                $flagFile,
                'invalid',
            );
            $this->signalEachWorker(
                SIGKILL,
                'accepting no connections until a reload succeeds',
            );

            self::assertFalse($this->bindsUser($this->buildClient('tcp')));

            file_put_contents(
                $flagFile,
                'allow-anonymous',
            );
            $this->signalEachWorker(
                SIGHUP,
                'server starting...',
            );

            $response = $this->buildClient('tcp')
                ->send(Operations::bindAnonymously())
                ?->getResponse();

            self::assertInstanceOf(
                BindResponse::class,
                $response,
            );
            self::assertSame(
                ResultCode::SUCCESS,
                $response->getResultCode(),
            );
        } finally {
            @unlink($flagFile);
        }
    }

    protected function reloadServer(): void
    {
        $this->signalEachWorker(
            SIGHUP,
            'Server configuration reloaded',
        );
    }

    protected static function runnerArgs(): array
    {
        return [
            '--runner=swoole',
            '--workers=2',
        ];
    }

    protected static function isRunnerAvailable(): bool
    {
        return extension_loaded('swoole');
    }

    private function signalEachWorker(
        int $signal,
        string $marker,
    ): void {
        foreach ($this->workerPids() as $pid) {
            posix_kill(
                $pid,
                $signal,
            );
            $this->waitForServerOutput($marker);
        }
    }

    /**
     * @return list<int>
     */
    private function workerPids(): array
    {
        $pids = [];
        exec(
            'pgrep -P ' . $this->serverPid(),
            $pids,
        );

        return array_map(
            intval(...),
            $pids,
        );
    }
}
