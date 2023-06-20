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

namespace FreeDSx\Ldap\Sync\Result;

use ArrayIterator;
use Countable;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use IteratorAggregate;
use Traversable;
use function count;

class SyncIdSetResult implements Countable, IteratorAggregate
{
    private ?SyncIdSet $idSet = null;

    public function __construct(private readonly LdapMessageResponse $message)
    {
    }

    public function getMessage(): LdapMessageResponse
    {
        return $this->message;
    }

    /**
     * Are the entries for this set deleted?
     */
    public function isDeleted(): bool
    {
        return (bool) $this->getSyncIdSet()
            ->getRefreshDeletes();
    }

    /**
     * Are the entries for this set still present?
     */
    public function isPresent(): bool
    {
        return !$this->getSyncIdSet()
                ->getRefreshDeletes();
    }

    /**
     * An array of string UUIDs for this set.
     *
     * @return string[]
     */
    public function getEntryUuids(): array
    {
        return $this->getSyncIdSet()
            ->getEntryUuids();
    }

    private function getSyncIdSet(): SyncIdSet
    {
        if ($this->idSet !== null) {
            return $this->idSet;
        }
        $idSet = $this->message->getResponse();

        if (!$idSet instanceof SyncIdSet) {
            throw new RuntimeException(sprintf(
                'Expected an instance of "%s", but get "%s".',
                SyncIdSet::class,
                get_class($idSet),
            ));
        }
        $this->idSet = $idSet;

        return $this->idSet;
    }

    /**
     * The cookie to be used following this sync set.
     */
    public function getCookie(): ?string
    {
        return $this->getSyncIdSet()
            ->getCookie();
    }

    /**
     * The number of impacted entries.
     *
     * {@inheritDoc}
     */
    public function count(): int
    {
        return count($this->getEntryUuids());
    }

    /**
     * @return Traversable<string>
     */
    public function getIterator(): Traversable
    {
        return new ArrayIterator($this->getEntryUuids());
    }
}
