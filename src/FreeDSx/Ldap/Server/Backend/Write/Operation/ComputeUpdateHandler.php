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
use FreeDSx\Ldap\Server\Backend\Write\Command\ComputeUpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Modifies an entry with changes derived from its current state, under a lock a concurrent writer cannot cross.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ComputeUpdateHandler
{
    use AppliesEntryUpdate;

    public function __construct(
        private TransactionalEntryWrite $writes,
        private EntryMutation $mutation,
        private EntryPlacementGuard $placement,
    ) {}

    /**
     * @throws OperationException
     */
    public function handle(
        ComputeUpdateCommand $command,
        WriteContext $context,
    ): void {
        $this->writes->updateIfPresent(
            $command->dn->normalize(),
            $context,
            fn(Entry $current): ?Entry => $this->computed(
                $command,
                $context,
                $current,
            ),
        );
    }

    /**
     * The entry the computed changes leave behind, or null when they turn out to be none.
     *
     * @throws OperationException
     */
    private function computed(
        ComputeUpdateCommand $command,
        WriteContext $context,
        Entry $current,
    ): ?Entry {
        $changes = ($command->compute)($current);

        if ($changes === []) {
            return null;
        }

        return $this->updated(
            new UpdateCommand(
                $command->dn,
                $changes,
            ),
            $context,
            $current,
        );
    }
}
