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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation\SubtreeDelete;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\UnrecordedChanges;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Write\Operation\LockedEntryAccess;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

use function array_filter;
use function array_flip;
use function array_map;
use function array_values;
use function in_array;

/**
 * Removes a subtree a chunk at a time, each chunk in one transaction that leaves no child without its parent.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SubtreeChunkRemover
{
    public function __construct(
        private LockedEntryAccess $locked,
        private SubtreeEnumerator $subtree,
        private WriteEntryInterface $storage,
        private ChangeRecorderInterface $changeRecorder = new UnrecordedChanges(),
    ) {}

    /**
     * The entries beneath the base and the base itself, in the order to remove them.
     */
    public function queueFor(Dn $base): DeletionQueue
    {
        return new DeletionQueue(
            $this->subtree,
            $base,
        );
    }

    /**
     * One transaction, removing those of the chunk it could lock that leave no child behind.
     *
     * @param list<string> $chunk canonical DNs, each after its children
     *
     * @throws OperationException
     */
    public function removeChunk(
        Dn $base,
        array $chunk,
        WriteContext $context,
    ): ChunkOutcome {
        return $this->locked->withEntry(
            $base,
            $context,
            fn(Entry $entry, array $held): ChunkOutcome => $this->removeHeld(
                $base,
                self::heldInWalkOrder(
                    $chunk,
                    $held,
                ),
                $context,
            ),
            // Removing an entry takes its links with it.
            new EntryProjection(linkCap: 0),
            array_map(
                Dn::fromCanonical(...),
                $chunk,
            ),
        );
    }

    /**
     * @param list<string> $members canonical DNs, each after its children
     */
    private function removeHeld(
        Dn $base,
        array $members,
        WriteContext $context,
    ): ChunkOutcome {
        $strays = $this->subtree->childrenOutside($members);
        $blocked = DeletionQueue::blockedBy(
            $members,
            $strays,
        );
        $removable = self::without(
            $members,
            $blocked,
        );

        return new ChunkOutcome(
            $this->remove(
                $removable,
                $context,
            ),
            in_array(
                $base->toString(),
                $removable,
                true,
            ),
            $strays,
            $blocked,
        );
    }

    /**
     * @param list<string> $dns canonical DNs, each after its children
     */
    private function remove(
        array $dns,
        WriteContext $context,
    ): int {
        $dnList = array_map(
            Dn::fromCanonical(...),
            $dns,
        );
        $preImages = $this->changeRecorder->records()
            ? $this->subtree->entriesAt($dnList)
            : [];
        $removed = $this->storage->removeAll($dnList);
        $this->changeRecorder->recordDeletes(
            $preImages,
            $context,
        );

        return $removed;
    }

    /**
     * An entry gone by the time the chunk is locked is not held, and is left out rather than removed unlocked.
     *
     * @param list<string> $chunk canonical DNs
     * @param list<Dn> $held
     *
     * @return list<string> canonical DNs, in the order of the chunk
     */
    private static function heldInWalkOrder(
        array $chunk,
        array $held,
    ): array {
        $isHeld = array_flip(array_map(
            static fn(Dn $dn): string => $dn->normalizedString(),
            $held,
        ));

        return array_values(array_filter(
            $chunk,
            static fn(string $dn): bool => isset($isHeld[$dn]),
        ));
    }

    /**
     * @param list<string> $dns
     * @param list<string> $excluded
     *
     * @return list<string> in the order given
     */
    private static function without(
        array $dns,
        array $excluded,
    ): array {
        $isExcluded = array_flip($excluded);

        return array_values(array_filter(
            $dns,
            static fn(string $dn): bool => !isset($isExcluded[$dn]),
        ));
    }
}
