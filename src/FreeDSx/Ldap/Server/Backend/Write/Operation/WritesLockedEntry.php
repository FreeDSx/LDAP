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

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\RowLockableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Opens the atomic write and takes the entry's row lock ahead of the body.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait WritesLockedEntry
{
    /**
     * @param Closure(): void $body
     * @throws OperationException
     */
    private function writeLocked(
        Dn $dn,
        Closure $body,
    ): void {
        $this->storage->atomic(function () use ($dn, $body): void {
            $this->lockForWrite($dn);
            $body();
        });
    }

    /**
     * Locates the entry under the lock, so a missing target answers before any control the write carries is evaluated.
     *
     * @param Closure(Entry): void $body
     * @throws OperationException
     */
    private function writeLockedEntry(
        Dn $dn,
        WriteContext $context,
        Closure $body,
    ): void {
        $this->writeLocked(
            $dn,
            function () use ($dn, $context, $body): void {
                // @todo Unbounded because the whole derived entry is stored back; leave linked attributes out once writes apply them as deltas.
                $current = $this->locator->findOrFail(
                    $dn,
                    EntryProjection::unbounded(),
                );
                $context->controlEvaluator()?->evaluateTarget($current);
                $body($current);
            },
        );
    }

    private function lockForWrite(Dn $dn): void
    {
        if (!$this->storage instanceof RowLockableInterface) {
            return;
        }

        $this->storage->lockForWrite($dn);
    }
}
