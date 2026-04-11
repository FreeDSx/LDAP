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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use LogicException;

/**
 * Routes a write command to the appropriate entry-level operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class WriteEntryOperationHandler
{
    public function apply(
        Entry $entry,
        WriteRequestInterface $command,
    ): Entry {
        return match (true) {
            $command instanceof UpdateCommand => (new UpdateOperation())->execute($entry, $command),
            $command instanceof MoveCommand => (new MoveOperation())->execute($entry, $command),
            default => throw new LogicException(
                sprintf('No entry operation handler for %s', $command::class),
            ),
        };
    }
}
