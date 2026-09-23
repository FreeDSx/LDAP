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
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryLocator;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Hands a write its target under the lock that keeps a concurrent writer out of the same entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LockedEntryAccess
{
    public function __construct(
        private TransactionalWriteInterface $transaction,
        private RowLockableInterface $locks,
        private EntryLocator $locator,
        private ReadEntryInterface $reader,
    ) {}

    /**
     * Locates the entry under the lock, so a missing target answers before any control the write carries is evaluated.
     *
     * @template TResult
     *
     * @param Closure(Entry): TResult $body
     *
     * @return TResult
     *
     * @throws OperationException when nothing is stored at the DN
     */
    public function withEntry(
        Dn $dn,
        WriteContext $context,
        Closure $body,
        EntryProjection $projection = new EntryProjection(linkCap: null),
    ): mixed {
        return $this->locked($dn, function () use ($dn, $context, $body, $projection): mixed {
            $current = $this->locator->findOrFail(
                $dn,
                $projection,
            );
            $context->controlEvaluator()?->evaluateTarget($current);

            return $body($current);
        });
    }

    /**
     * The same for a write the server raised itself, where an entry that is gone is an answer rather than a failure.
     *
     * @template TResult
     *
     * @param Closure(Entry): TResult $body
     *
     * @return ?TResult null when nothing is stored at the DN
     */
    public function withEntryIfPresent(
        Dn $dn,
        Closure $body,
    ): mixed {
        return $this->locked($dn, function () use ($dn, $body): mixed {
            // Stored back with its links left alone.
            $current = $this->reader->find(
                $dn,
                new EntryProjection(linkCap: 0),
            );

            return $current === null
                ? null
                : $body($current);
        });
    }

    /**
     * @template TResult
     *
     * @param Closure(): TResult $body
     *
     * @return TResult
     */
    private function locked(
        Dn $dn,
        Closure $body,
    ): mixed {
        return $this->transaction->atomic(function () use ($dn, $body): mixed {
            $this->locks->lockForWrite($dn);

            return $body();
        });
    }
}
