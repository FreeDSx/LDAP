<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;

class SyncEntryResult
{
    use SyncResultTrait;

    public function __construct(private readonly EntryResult $entryResult)
    {}

    public function getMessage(): LdapMessageResponse
    {
        return $this->entryResult->getMessage();
    }

    public function getEntry(): Entry
    {
        return $this->entryResult->getEntry();
    }
}
