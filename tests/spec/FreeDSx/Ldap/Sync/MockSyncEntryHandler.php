<?php

declare(strict_types=1);

namespace spec\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Session;

/**
 * Used only for collaborator purposes to test sync entry handling invocation.
 *
 * @internal
 */
class MockSyncEntryHandler
{
    public function __invoke(
        SyncEntryResult $syncEntryResult,
        Session $session
    ): void {}
}
