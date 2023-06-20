<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;

trait SyncResultTrait
{
    private ?SyncStateControl $syncState = null;

    /**
     * The raw LDAP Message response for the sync.
     */
    abstract public function getMessage(): LdapMessageResponse;

    /**
     * The state of the sync result. This is one of:
     *
     *   - {@see SyncStateControl::STATE_PRESENT}
     *   - {@see SyncStateControl::STATE_ADD}
     *   - {@see SyncStateControl::STATE_MODIFY}
     *   - {@see SyncStateControl::STATE_DELETE}
     *
     */
    public function getState(): int
    {
        return $this->getSyncStateControl()
            ->getState();
    }

    /**
     * Convenience method to check for a specific state. For the states possible {@see self::getState()}.
     */
    public function isState(int $state): bool
    {
        return $this->getState() === $state;
    }

    /**
     * Get the cookie associated with this sync session / sync state.
     */
    public function getCookie(): ?string
    {
        return $this->getSyncStateControl()
            ->getCookie();
    }

    /**
     * Get the UUID of the entry for this sync result.
     */
    public function getEntryUuid(): string
    {
        return $this->getSyncStateControl()
            ->getEntryUuid();
    }

    private function getSyncStateControl(): SyncStateControl
    {
        if ($this->syncState !== null) {
            return $this->syncState;
        }

        $syncState = $this->getMessage()
            ->controls()
            ->getByClass(SyncStateControl::class);

        if ($syncState === null) {
            throw new RuntimeException('Expected a SyncStateControl, but none was found.');
        }

        $this->syncState = $syncState;

        return $this->syncState;
    }
}
