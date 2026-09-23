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
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\UnrecordedChanges;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Stores the entry a write leaves behind: built inside the transaction, held to its references, answered for once stored.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class TransactionalEntryWrite
{
    public function __construct(
        private WriteEntryInterface $writes,
        private TransactionalWriteInterface $transaction,
        private LockedEntryAccess $locked,
        private ReferenceGuard $references,
        private ChangeRecorderInterface $changeRecorder = new UnrecordedChanges(),
    ) {}

    /**
     * Opens the transaction the entry is built and added in.
     *
     * @param Closure(): Entry $produce Runs inside the transaction, so a reissued attempt builds the entry again.
     * @param bool $replaceExisting Overwrite an entry already at the DN rather than refusing it.
     *
     * @throws OperationException
     */
    public function add(
        WriteContext $context,
        Closure $produce,
        bool $replaceExisting = false,
    ): Entry {
        return $this->transaction->atomic(function () use ($produce, $context, $replaceExisting): Entry {
            $entry = $produce();

            if ($replaceExisting) {
                $this->writes->store(
                    $entry,
                    rebuildIndexes: true,
                );
            } else {
                $this->writes->insert($entry);
            }
            $this->resolved($entry, $context);

            // Journaled within the same transaction, so a record can never outlive the write it describes.
            $this->changeRecorder->recordAdd(
                $entry,
                $context,
            );

            return $entry;
        });
    }

    /**
     * Stores the entry a modify leaves behind, with the target locked and loaded for the producer to work from.
     *
     * @param LinkDelta $links Linked values the modify changes, which its entry is then left without.
     * @param Closure(Entry): ?Entry $produce Answers null when the change turns out to be nothing to write.
     *
     * @return ?Entry what was stored, or null when the producer had nothing to write
     *
     * @throws OperationException when nothing is stored at the DN
     */
    public function update(
        Dn $dn,
        LinkDelta $links,
        WriteContext $context,
        Closure $produce,
    ): ?Entry {
        return $this->locked->withEntry(
            $dn,
            $context,
            fn(Entry $current): ?Entry => $this->stored(
                $produce($current),
                $links,
                $context,
            ),
            // A delta names what it changes, so the entry is read without the values it leaves alone.
            $links->isEmpty()
                ? EntryProjection::unbounded()
                : new EntryProjection(linkCap: 0),
        );
    }

    /**
     * The same for a write the server raised itself, where an entry that is gone is an answer rather than a failure.
     *
     * @param Closure(Entry): ?Entry $produce
     *
     * @throws OperationException
     */
    public function updateIfPresent(
        Dn $dn,
        WriteContext $context,
        Closure $produce,
    ): ?Entry {
        return $this->locked->withEntryIfPresent(
            $dn,
            fn(Entry $current): ?Entry => $this->stored(
                $produce($current),
                new LinkDelta(),
                $context,
            ),
        );
    }

    /**
     * Removes the entry with it locked, so what is journaled is what was actually taken away.
     *
     * @param Closure(Entry): void $check Runs with the target loaded, to refuse the removal before it happens.
     *
     * @throws OperationException
     */
    public function delete(
        Dn $dn,
        WriteContext $context,
        Closure $check,
    ): void {
        $this->locked->withEntry(
            $dn,
            $context,
            function (Entry $current) use ($dn, $context, $check): void {
                $check($current);

                $this->writes->remove($dn);
                $this->changeRecorder->recordDelete(
                    $current,
                    $context,
                );
            },
            // Removing an entry takes its links with it, so journaling them would only record what is already gone.
            new EntryProjection(linkCap: 0),
        );
    }

    /**
     * @throws OperationException
     */
    private function stored(
        ?Entry $entry,
        LinkDelta $links,
        WriteContext $context,
    ): ?Entry {
        if ($entry === null) {
            return null;
        }

        $this->writes->store(
            $entry,
            links: $links,
        );
        $this->resolved(
            $entry,
            $context,
        );

        $this->changeRecorder->recordModify(
            $entry,
            $context,
        );

        return $entry;
    }

    /**
     * @throws OperationException when a value of the entry names an entry the directory does not hold
     */
    private function resolved(
        Entry $entry,
        WriteContext $context,
    ): void {
        $this->references->assertResolved(
            $entry->getDn(),
            $context,
        );
    }
}
