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
    use SyncResultTrait;

    private ?SyncIdSet $idSet = null;

    public function __construct(private readonly LdapMessageResponse $message)
    {}

    public function getMessage(): LdapMessageResponse
    {
        return $this->message;
    }

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
