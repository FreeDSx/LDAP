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
use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Initialization\RequirementInterface;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerOptions;

/**
 * An in-memory SQLite database belongs to one connection, and the Swoole runner opens one per coroutine.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class CoroutineSafeStorageRequirement implements RequirementInterface
{
    public function __construct(private ServerOptions $options) {}

    public function assertMet(): void
    {
        $storageConfig = $this->options->getStorageConfig();

        if (!$this->options->isRunnerMode(RunnerMode::Swoole) || !$storageConfig instanceof PdoConfig) {
            return;
        }
        if ($storageConfig->isMultiProcessSafe()) {
            return;
        }

        throw new RuntimeException(
            'The Swoole runner opens a connection per coroutine, so an in-memory SQLite database is not supported.',
        );
    }
}
