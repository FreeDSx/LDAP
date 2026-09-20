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
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Removes one entry, which has to be a leaf.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DeleteEntryHandler
{
    public function __construct(
        private TransactionalEntryWrite $writes,
        private EntryPlacementGuard $placement,
    ) {}

    /**
     * @throws OperationException
     */
    public function handle(
        DeleteCommand $command,
        WriteContext $context,
    ): void {
        $this->writes->delete(
            $command->dn->normalize(),
            $context,
            function (Entry $current) use ($command): void {
                $this->placement->assertDeletePlacement($command->dn);
            },
        );
    }
}
