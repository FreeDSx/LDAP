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

/**
 * @api
 */
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
     *
     * @api
     */
    public function isState(int $state): bool
    {
        return $this->getState() === $state;
    }

    /**
     * {@see SyncStateControl::isAdd()}
     *
     * @api
     */
    public function isAdd(): bool
    {
        return $this->getSyncStateControl()
            ->isAdd();
    }

    /**
     * {@see SyncStateControl::isDelete()}
     *
     * @api
     */
    public function isDelete(): bool
    {
        return $this->getSyncStateControl()
            ->isDelete();
    }

    /**
     * {@see SyncStateControl::isModify()}
     *
     * @api
     */
    public function isModify(): bool
    {
        return $this->getSyncStateControl()
            ->isModify();
    }

    /**
     * {@see SyncStateControl::isPresent()}
     *
     * @api
     */
    public function isPresent(): bool
    {
        return $this->getSyncStateControl()
            ->isPresent();
    }

    /**
     * Get the cookie associated with this sync session / sync state.
     *
     * @api
     */
    public function getCookie(): ?string
    {
        return $this->getSyncStateControl()
            ->getCookie();
    }

    /**
     * Get the UUID of the entry for this sync result.
     *
     * @api
     */
    public function getEntryUuid(): string
    {
        return $this->getSyncStateControl()
            ->getEntryUuid();
    }

    /**
     * The same UUID in the dashed form entries carry it in, rather than the 16 bytes the control does.
     *
     * @api
     */
    public function getDecodedEntryUuid(): string
    {
        return $this->getSyncStateControl()
            ->decodedUuid();
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
