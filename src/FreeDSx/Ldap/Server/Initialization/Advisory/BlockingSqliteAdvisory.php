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

namespace FreeDSx\Ldap\Server\Initialization\Advisory;

use FreeDSx\Ldap\Server\Config\Storage\PdoConfig;
use FreeDSx\Ldap\Server\Config\Storage\PdoDriver;
use FreeDSx\Ldap\Server\Initialization\AdvisoryInterface;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerOptions;

use function defined;

/**
 * A Swoole build without its SQLite hook blocks the whole worker while SQLite waits on a lock.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class BlockingSqliteAdvisory implements AdvisoryInterface
{
    public function __construct(private ServerOptions $options) {}

    public function warnings(): array
    {
        $storageConfig = $this->options->getStorageConfig();

        if (!$this->options->isRunnerMode(RunnerMode::Swoole) || !$storageConfig instanceof PdoConfig) {
            return [];
        }
        if ($storageConfig->getDriver() !== PdoDriver::Sqlite || defined('SWOOLE_HOOK_PDO_SQLITE')) {
            return [];
        }

        return [InitializationWarning::concurrencyLimited(ConcurrencyLimitReason::StorageBlocksWorker)];
    }
}
