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

namespace FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;

class SyncEntryResult
{
    use SyncResultTrait;

    public function __construct(private readonly EntryResult $entryResult)
    {
    }

    public function getMessage(): LdapMessageResponse
    {
        return $this->entryResult->getMessage();
    }

    public function getEntry(): Entry
    {
        return $this->entryResult->getEntry();
    }
}
