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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Control\SubtreeDeleteProgressControl;

/**
 * How far one subtree delete request has got across its transactions.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SubtreeDeleteProgress
{
    private int $deleted = 0;

    private bool $complete = false;

    private int $idleRounds = 0;

    public function record(ChunkOutcome $outcome): void
    {
        $this->deleted += $outcome->removed;
        $this->complete = $this->complete || $outcome->baseRemoved;
        $this->idleRounds = $outcome->removed === 0
            ? $this->idleRounds + 1
            : 0;
    }

    public function deleted(): int
    {
        return $this->deleted;
    }

    public function isComplete(): bool
    {
        return $this->complete;
    }

    /**
     * Transactions in a row that removed nothing.
     */
    public function idleRounds(): int
    {
        return $this->idleRounds;
    }

    public function toControl(): SubtreeDeleteProgressControl
    {
        return new SubtreeDeleteProgressControl($this->deleted);
    }
}
