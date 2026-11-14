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

use FreeDSx\Ldap\Server\Initialization\AdvisoryInterface;
use FreeDSx\Ldap\Server\Initialization\InitializationWarning;
use FreeDSx\Ldap\Server\Logging\ConcurrencyLimitReason;
use FreeDSx\Ldap\Server\Resources\OpenFileLimit;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * A Swoole worker holds every client's open files in one process and can reach the open-file limit first.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class OpenFileLimitAdvisory implements AdvisoryInterface
{
    public function __construct(
        private ServerListenerOptionsInterface $options,
        private OpenFileLimit $openFileLimit,
        private int $descriptorsPerClient,
    ) {}

    public function warnings(): array
    {
        if (!$this->options->isRunnerMode(RunnerMode::Swoole)) {
            return [];
        }

        $maxConnections = $this->options->getNetworkConfig()->getMaxConnections();
        if (!$this->openFileLimit->isReachedBefore($maxConnections, $this->descriptorsPerClient)) {
            return [];
        }

        return [
            InitializationWarning::concurrencyLimited(
                ConcurrencyLimitReason::OpenFileLimit,
                [
                    'open_file_limit' => $this->openFileLimit->getSoftLimit(),
                    'max_connections' => $maxConnections,
                    'descriptors_per_client' => $this->descriptorsPerClient,
                ],
            ),
        ];
    }
}
