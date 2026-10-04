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

namespace FreeDSx\Ldap\Server\ServerRunner\Pcntl;

use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Process\Channel\ChildChannel;

/**
 * How one connection child reports its operations to the parent.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ChildReporter
{
    public function __construct(
        private ChildChannel $channel,
        private OperationRollupCoordinator $operationRollup,
    ) {}

    public function channel(): ChildChannel
    {
        return $this->channel;
    }

    /**
     * In the parent after the fork: keep only the end it reads.
     */
    public function inParent(): void
    {
        $this->channel->parentKeepRead();
    }

    /**
     * In the child after the fork: keep only the end it writes, and report nothing it inherited from the parent.
     */
    public function inChild(): void
    {
        $this->channel->childKeepWrite();
        $this->operationRollup->enterChild($this->channel);
    }

    /**
     * In the child before it exits: send what is left.
     */
    public function finish(): void
    {
        $this->operationRollup->finish();
    }

    /**
     * When the fork failed and no child will report.
     */
    public function close(): void
    {
        $this->channel->close();
    }
}
