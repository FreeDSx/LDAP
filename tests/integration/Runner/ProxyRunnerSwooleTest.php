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

use Tests\Integration\FreeDSx\Ldap\Runner\Concern\SharedRequestBudgetTestsTrait;

use function extension_loaded;

/**
 * Runs the shared proxy runner suite against the Swoole ServerRunner.
 */
final class ProxyRunnerSwooleTest extends ProxyRunnerTestCase
{
    use SharedRequestBudgetTestsTrait;

    public function setUp(): void
    {
        $this->requireSwoole();

        parent::setUp();
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
