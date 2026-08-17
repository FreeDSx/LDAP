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
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
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
    private readonly UpdateOperation $update;

    public function __construct(
        EqualityComparatorResolver $equalityResolver,
        private readonly MoveOperation $move = new MoveOperation(),
    ) {
        $this->update = new UpdateOperation($equalityResolver);
    }

    public function apply(
        Entry $entry,
        WriteRequestInterface $command,
    ): Entry {
        // Work on a copy so a command rejected by later validation leaves the stored entry untouched.
        $target = $entry->makeCopy();

        return match (true) {
            $command instanceof UpdateCommand => $this->update->execute($target, $command),
            $command instanceof MoveCommand => $this->move->execute($target, $command),
            default => throw new LogicException(
                sprintf('No entry operation handler for %s', $command::class),
            ),
        };
    }
}
