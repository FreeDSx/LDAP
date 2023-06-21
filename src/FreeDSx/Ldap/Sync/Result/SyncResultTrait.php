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
     * Is this for an entry that was added?
     */
    public function isAdd(): bool
    {
        return $this->getSyncStateControl()
            ->isAdd();
    }

    /**
     * Is this for an entry that was deleted?
     */
    public function isDelete(): bool
    {
        return $this->getSyncStateControl()
            ->isDelete();
    }

    /**
     * Is this for an entry that was modified?
     */
    public function isModify(): bool
    {
        return $this->getSyncStateControl()
            ->isModify();
    }

    /**
     * Is this for an entry that is still present / has not changed?
     */
    public function isPresent(): bool
    {
        return $this->getSyncStateControl()
            ->isPresent();
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
