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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * The entry a modify leaves behind, however its changes were arrived at.
 *
 * Used by handlers holding a mutation and a placement guard.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait AppliesEntryUpdate
{
    use AppliesSystemChanges;

    /**
     * The entry the modify leaves behind, before anything stores it.
     *
     * @throws OperationException
     */
    private function updated(
        UpdateCommand $command,
        WriteContext $context,
        Entry $current,
    ): Entry {
        $updated = $this->mutation->forUpdate(
            $current,
            $command,
            $context,
        );
        $this->placement->assertUpdatePlacement(
            $updated,
            $command->dn->normalize(),
            $context->isSystem(),
        );
        $this->applySystemChanges(
            $updated,
            $command->systemChanges,
        );
        $context->controlEvaluator()?->captureResult($updated);

        return $updated;
    }
}
