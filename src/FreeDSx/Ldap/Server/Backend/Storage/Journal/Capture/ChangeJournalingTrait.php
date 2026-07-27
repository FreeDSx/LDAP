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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture;

use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;

/**
 * Shared ChangeJournalingInterface scaffolding for storage adapters.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ChangeJournalingTrait
{
    private readonly ?ChangeJournalInterface $journal;

    public function appendChange(PendingChange $change): void
    {
        $this->journal?->append($change);
    }

    public function changeJournal(): ?ChangeJournalInterface
    {
        return $this->journal;
    }
}
