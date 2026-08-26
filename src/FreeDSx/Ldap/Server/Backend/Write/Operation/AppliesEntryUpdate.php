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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * The modify every update shares, however its changes were arrived at.
 *
 * Used by handlers holding a storage, locator, mutation, placement guard and optional change recorder.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait AppliesEntryUpdate
{
    /**
     * Runs within an already-open write; the caller owns the transaction.
     *
     * @throws OperationException
     */
    private function applyUpdate(
        UpdateCommand $command,
        WriteContext $context,
    ): void {
        $dn = $command->dn->normalize();
        $updated = $this->mutation->forUpdate(
            $this->locator->findOrFail($dn),
            $command,
            $context,
        );
        $this->placement->assertUpdatePlacement(
            $updated,
            $dn,
            $context->isSystem(),
        );

        $this->storage->store($updated);
        $this->changeRecorder?->recordModify(
            $updated,
            $context,
        );
    }
}
