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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\ReferenceIntegrityInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

use function sprintf;

/**
 * Refuses a write naming an entry the directory does not hold.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReferenceGuard
{
    public function __construct(private ReferenceIntegrityInterface $references) {}

    /**
     * Runs inside the write's own transaction. Refusing it takes the write with it.
     *
     * @throws OperationException when a value of the entry names an entry that is not stored
     */
    public function assertResolved(
        Dn $owner,
        WriteContext $context,
    ): void {
        // A bulk load is ordered by its source rather than by reference, so it settles at the end of its own batch.
        if ($context->bulkLoadOptions() !== null) {
            return;
        }
        $unresolved = $this->references->unresolvedReferences($owner);

        if ($unresolved === []) {
            return;
        }

        throw new OperationException(
            sprintf(
                'The attribute "%s" of entry "%s" names an entry that does not exist.',
                $unresolved[0],
                $owner->toString(),
            ),
            ResultCode::CONSTRAINT_VIOLATION,
        );
    }

    /**
     * The end of a batch that was allowed to name entries it had not stored yet.
     *
     * @throws OperationException when anything the batch wrote is still unresolved
     */
    public function assertNothingPending(): void
    {
        if (!$this->references->hasUnresolvedReferences()) {
            return;
        }

        throw new OperationException(
            'An entry names another that the directory does not hold.',
            ResultCode::CONSTRAINT_VIOLATION,
        );
    }
}
