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
use FreeDSx\Ldap\Server\ServerRunner\Swoole\WorkerLimit;

/**
 * Several Swoole workers are clamped to one when the storage or the listener cannot be shared between processes.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class WorkerClampAdvisory implements AdvisoryInterface
{
    public function __construct(private WorkerLimit $limit) {}

    public function warnings(): array
    {
        $reason = $this->limit->reason();
        if ($reason === null) {
            return [];
        }

        return [
            InitializationWarning::concurrencyLimited(
                $reason,
                ['requested_workers' => $this->limit->requested()],
            ),
        ];
    }
}
