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
use FreeDSx\Ldap\Server\Resources\MemoryLimit;
use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\ServerListenerOptionsInterface;

/**
 * A Swoole worker holds every client's memory in one process and can reach the memory limit first.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class MemoryLimitAdvisory implements AdvisoryInterface
{
    /**
     * @param int $heldRequestSize the bytes the requests of one process may hold at once, in effect, or 0 for no limit.
     */
    public function __construct(
        private ServerListenerOptionsInterface $options,
        private MemoryLimit $memoryLimit,
        private int $heldRequestSize,
    ) {}

    public function warnings(): array
    {
        if (!$this->options->isRunnerMode(RunnerMode::Swoole)) {
            return [];
        }

        $maxConnections = $this->options->getNetworkConfig()->getMaxConnections();
        if (!$this->memoryLimit->isReachedBefore($maxConnections, $this->heldRequestSize)) {
            return [];
        }

        return [
            InitializationWarning::concurrencyLimited(
                ConcurrencyLimitReason::MemoryLimit,
                [
                    'memory_limit' => $this->memoryLimit->getBytes(),
                    'max_connections' => $maxConnections,
                    'max_held_request_size' => $this->heldRequestSize,
                ],
            ),
        ];
    }
}
