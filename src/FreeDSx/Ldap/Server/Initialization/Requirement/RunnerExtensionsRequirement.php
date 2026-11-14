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

namespace FreeDSx\Ldap\Server\Initialization\Requirement;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Initialization\RequirementInterface;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

use function extension_loaded;

/**
 * The extensions the configured runner is built on must be loaded.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class RunnerExtensionsRequirement implements RequirementInterface
{
    public function __construct(private ServerListenerOptionsInterface $options) {}

    public function assertMet(): void
    {
        $isSwoole = $this->options->isRunnerMode(RunnerMode::Swoole);

        if ($isSwoole && !extension_loaded('swoole')) {
            throw new RuntimeException('The Swoole extension is required to use the Swoole runner.');
        }

        if (!$isSwoole && (!extension_loaded('pcntl') || !extension_loaded('posix'))) {
            throw new RuntimeException(
                'The pcntl and posix extensions are required to fork and manage child processes '
                . '(not available on Windows).',
            );
        }
    }
}
