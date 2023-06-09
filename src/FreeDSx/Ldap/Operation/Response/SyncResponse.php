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

namespace FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Operation\LdapResult;

/**
 * This response encapsulates the details of a sync request (RFC4533) from the search results / intermediate responses.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SyncResponse extends LdapResult
{
    /**
     * @var SyncResult[]|null
     */
    protected ?array $initial;

    /**
     * @var SyncResult[]|null
     */
    protected ?array $persist;

    /**
     * @var SyncResult[]|null
     */
    protected ?array $present;

    /**
     * @var SyncResult[]|null
     */
    protected ?array $deleted;

    protected string $cookie;

    /**
     * @param SyncResult[]|null $syncPresent
     * @param SyncResult[]|null $syncDeleted
     * @param SyncResult[]|null $syncInitial
     * @param SyncResult[]|null $syncPersist
     */
    public function __construct(
        LdapResult $result,
        string $cookie,
        ?array $syncPresent = [],
        ?array $syncDeleted = null,
        ?array $syncInitial = null,
        ?array $syncPersist = null
    ) {
        $this->cookie = $cookie;
        $this->initial = $syncInitial;
        $this->persist = $syncPersist;
        $this->present = $syncPresent;
        $this->deleted = $syncDeleted;

        parent::__construct(
            $result->resultCode,
            $result->dn,
            $result->diagnosticMessage,
            ...$result->referrals
        );
    }

    /**
     * @return SyncResult[]|null
     */
    public function getInitialContent(): ?array
    {
        return $this->initial;
    }

    /**
     * @return SyncResult[]|null
     */
    public function getPersistStage(): ?array
    {
        return $this->persist;
    }

    /**
     * @return SyncResult[]|null
     */
    public function getDeletedPhase(): ?array
    {
        return $this->deleted;
    }

    /**
     * @return SyncResult[]|null
     */
    public function getPresentPhase(): ?array
    {
        return $this->present;
    }

    public function getCookie(): string
    {
        return $this->cookie;
    }
}
