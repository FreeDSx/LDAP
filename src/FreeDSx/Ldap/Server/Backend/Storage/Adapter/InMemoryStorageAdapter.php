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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\WriteEntryOperationHandler;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WritableBackendTrait;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use Generator;

/**
 * An in-memory storage adapter backed by a plain PHP array.
 *
 * Suitable for single-process use cases: the Swoole server runner (all
 * connections share the same process memory), or pre-seeded read-only
 * use with the PCNTL runner (data seeded before run() is inherited by
 * all forked child processes).
 *
 * With the PCNTL runner, write operations performed by one child process
 * are not visible to other children or the parent.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class InMemoryStorageAdapter implements WritableLdapBackendInterface
{
    use StorageAdapterTrait;
    use WritableBackendTrait;

    /**
     * Entries keyed by their normalised (lowercased) DN string.
     *
     * @var array<string, Entry>
     */
    private array $entries = [];

    /**
     * Pre-populate the adapter with a set of entries.
     *
     * @param Entry[] $entries
     */
    public function __construct(
        array $entries = [],
        private readonly WriteEntryOperationHandler $entryHandler = new WriteEntryOperationHandler(),
    ) {
        foreach ($entries as $entry) {
            $this->entries[$this->normalise($entry->getDn())] = $entry;
        }
    }

    public function get(Dn $dn): ?Entry
    {
        return $this->entries[$this->normalise($dn)] ?? null;
    }

    public function search(SearchContext $context): Generator
    {
        $normBase = $this->normalise($context->baseDn);

        foreach ($this->entries as $normDn => $entry) {
            if ($this->isInScope($normDn, $normBase, $context->scope)) {
                yield $entry;
            }
        }
    }

    /**
     * @throws OperationException
     */
    public function add(AddCommand $command): void
    {
        $entry = $command->entry;
        $normDn = $this->normalise($entry->getDn());

        if (isset($this->entries[$normDn])) {
            throw new OperationException(
                sprintf('Entry already exists: %s', $entry->getDn()->toString()),
                ResultCode::ENTRY_ALREADY_EXISTS,
            );
        }

        $this->entries[$normDn] = $entry;
    }

    /**
     * @throws OperationException
     */
    public function delete(DeleteCommand $command): void
    {
        $normDn = $this->normalise($command->dn);

        foreach (array_keys($this->entries) as $key) {
            if ($this->isInScope($key, $normDn, SearchRequest::SCOPE_SINGLE_LEVEL)) {
                throw new OperationException(
                    sprintf('Entry "%s" has subordinate entries and cannot be deleted.', $command->dn->toString()),
                    ResultCode::NOT_ALLOWED_ON_NON_LEAF,
                );
            }
        }

        unset($this->entries[$normDn]);
    }

    public function update(UpdateCommand $command): void
    {
        $normDn = $this->normalise($command->dn);

        if (!isset($this->entries[$normDn])) {
            throw new OperationException(
                sprintf('No such object: %s', $command->dn->toString()),
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $this->entries[$normDn] = $this->entryHandler->apply(
            $this->entries[$normDn],
            $command,
        );
    }

    public function move(MoveCommand $command): void
    {
        $normOld = $this->normalise($command->dn);

        if (!isset($this->entries[$normOld])) {
            throw new OperationException(
                sprintf('No such object: %s', $command->dn->toString()),
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $newEntry = $this->entryHandler->apply(
            $this->entries[$normOld],
            $command,
        );
        unset($this->entries[$normOld]);

        $this->entries[$this->normalise($newEntry->getDn())] = $newEntry;
    }
}
