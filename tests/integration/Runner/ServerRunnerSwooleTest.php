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

use Tests\Support\FreeDSx\Ldap\RequiresOperatingSystemTrait;

use function extension_loaded;

/**
 * Runs the shared runner suite against the Swoole ServerRunner.
 */
final class ServerRunnerSwooleTest extends ServerRunnerTestCase
{
    use RequiresOperatingSystemTrait;

    public function setUp(): void
    {
        $this->requireSwoole();

        parent::setUp();
    }

    public function testAcceptFailuresPastTheOpenFileLimitAreLoggedOnceWithTheirRecovery(): void
    {
        $this->requireLinux('Other kernels drop a client that cannot be accepted, leaving no failure to report.');
        $this->createServerProcess(
            'tcp',
            ['--log'],
            self::OPEN_FILE_LIMIT,
        );
        $clients = $this->openRawClients(100);

        try {
            $this->waitForServerOutput('Failed to accept incoming connection.');
        } finally {
            $this->closeRawClients($clients);
        }

        $this->authenticateUser();
        self::assertStringNotContainsString(
            'Failed to accept incoming connection.',
            $this->waitForServerOutput('Accepting incoming connections recovered.'),
        );
    }

    protected static function runnerArgs(): array
    {
        return ['--runner=swoole'];
    }

    protected static function isRunnerAvailable(): bool
    {
        return extension_loaded('swoole');
    }
}
