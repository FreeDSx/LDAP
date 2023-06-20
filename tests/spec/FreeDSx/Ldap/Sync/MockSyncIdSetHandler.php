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

namespace spec\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;

/**
 * Used only for collaborator purposes to test sync entry handling invocation.
 *
 * @internal
 */
class MockSyncIdSetHandler
{
    public function __invoke(
        SyncIdSetResult $result,
        Session $session,
    ): void {
    }
}
