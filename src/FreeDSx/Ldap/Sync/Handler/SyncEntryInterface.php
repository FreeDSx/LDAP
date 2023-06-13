<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Sync\Handler;

use FreeDSx\Ldap\Sync\Phase;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;

interface SyncEntryInterface
{
    public function syncEntry(
        SyncEntryResult $result,
        Phase $phase,
    ): void;
}
