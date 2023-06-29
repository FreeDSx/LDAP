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

namespace integration\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use integration\FreeDSx\Ldap\LdapTestCase;

class SyncReplTest extends LdapTestCase
{
    public function testItCanPerformPollingSync(): void
    {
        $entries = [];

        $client = $this->getClient();
        $this->bindClient($client);

        $client
            ->syncRepl()
            ->poll(fn (SyncEntryResult $result) => array_push($entries, $result));

        $this->assertGreaterThan(
            0,
            $entries,
        );
    }
}
