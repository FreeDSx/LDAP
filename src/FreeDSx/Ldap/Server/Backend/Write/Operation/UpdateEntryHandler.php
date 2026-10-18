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
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Operation\Linked\LinkedChangeReplay;
use FreeDSx\Ldap\Server\Backend\Write\Operation\Linked\LinkedChanges;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Modifies an entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class UpdateEntryHandler
{
    use AppliesEntryUpdate;

    public function __construct(
        private TransactionalEntryWrite $writes,
        private EntryMutation $mutation,
        private EntryPlacementGuard $placement,
        private LinkedChanges $linkedChanges,
        private LinkedChangeReplay $replay,
    ) {}

    /**
     * @throws OperationException
     */
    public function handle(
        UpdateCommand $command,
        WriteContext $context,
    ): void {
        $apart = $this->linkedChanges->changesApart(
            $command,
            $context,
        );
        $remaining = $this->linkedChanges->remaining(
            $command,
            $apart,
        );

        $this->writes->update(
            $command->dn->normalize(),
            $apart === []
                ? EntryProjection::unbounded()
                : new EntryProjection(linkCap: 0),
            $context,
            function (Entry $current) use ($apart, $remaining, $context): ModifiedEntry {
                $links = $this->replay->settle(
                    $apart,
                    $current->getDn(),
                );

                return new ModifiedEntry(
                    $this->updated(
                        $remaining,
                        $context,
                        $current,
                    ),
                    $links,
                );
            },
        );
    }
}
