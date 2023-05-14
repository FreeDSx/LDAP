<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use function is_array;

/**
 * Represents an entry / reference returned by the sync request, which includes the sync state.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SyncResult
{
    /**
     * @var SyncIdSet|Entry|LdapUrl[]
     */
    protected $result;

    /**
     * @var SyncStateControl|null
     */
    protected $syncState;

    /**
     * @param $result SyncIdSet|Entry|LdapUrl[]
     */
    public function __construct(
        $result,
        ?SyncStateControl $syncStateControl = null
    ) {
        $this->result = $result;
        $this->syncState = $syncStateControl;
    }

    public function isEntry(): bool
    {
        return $this->result instanceof Entry;
    }

    public function isReference(): bool
    {
        return is_array($this->result);
    }

    public function isIdSet(): bool
    {
        return $this->result instanceof SyncIdSet;
    }

    public function getSyncState(): ?SyncStateControl
    {
        return $this->syncState;
    }

    /**
     * @return SyncIdSet|Entry|LdapUrl[]
     */
    public function getResult()
    {
        return $this->result;
    }
}
