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
use FreeDSx\Ldap\ServerOptions;

use function sprintf;

/**
 * A runner that forks per connection needs storage every process shares, or a write vanishes with its connection.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ForkSafeStorageRequirement implements RequirementInterface
{
    public function __construct(private ServerOptions $options) {}

    public function assertMet(): void
    {
        $storageConfig = $this->options->getStorageConfig();

        // Swoole is exempt, since its workers share memory.
        if ($this->options->isRunnerMode(RunnerMode::Swoole) || $storageConfig->isMultiProcessSafe()) {
            return;
        }

        throw new RuntimeException(sprintf(
            'The %s runner forks per connection, so "%s" is not safe to use. See the docs for more details.',
            RunnerMode::Pcntl->name,
            $storageConfig::class,
        ));
    }
}
