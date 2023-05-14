<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Exception\CancelSyncException;
use FreeDSx\Ldap\Operation\Response\SyncResult;

/**
 * Used for receiving responses received to sync requests (RFC4533). Any method may throw a CancelSyncException to end
 * the sync currently in progress.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com
 */
interface SyncHandlerInterface
{
    /**
     * Called during a refresh present stage.
     *
     * @throws CancelSyncException
     */
    public function refreshPresent(SyncResult $syncResult): void;

    /**
     * Called during a refresh delete stage.
     *
     * @throws CancelSyncException
     */
    public function refreshDelete(SyncResult $syncResult): void;

    /**
     * Called during a persist stage for update notifications.
     *
     * @throws CancelSyncException
     */
    public function updatePoll(SyncResult $syncResult): void;

    /**
     * Called during an initial polling / refresh only stage.
     *
     * @throws CancelSyncException
     */
    public function initialPoll(SyncResult $syncResult): void;
}
