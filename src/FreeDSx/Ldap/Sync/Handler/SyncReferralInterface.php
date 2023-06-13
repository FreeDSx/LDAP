<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Sync\Handler;

use FreeDSx\Ldap\Sync\Phase;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;

interface SyncReferralInterface
{
    public function syncEntry(
        SyncIdSetResult $result,
        Phase $phase,
    ): void;
}
