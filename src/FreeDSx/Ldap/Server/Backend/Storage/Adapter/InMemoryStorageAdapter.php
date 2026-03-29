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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Search\Filter\PresentFilter;
use FreeDSx\Ldap\Server\Backend\SearchContext;
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
     */
    public function __construct(Entry ...$entries)
    {
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
        $dn = $command->dn;
        $childGenerator = $this->search(new SearchContext(
            baseDn: $dn,
            scope: SearchRequest::SCOPE_SINGLE_LEVEL,
            filter: new PresentFilter('objectClass'),
            attributes: [],
            typesOnly: false,
        ));

        if ($childGenerator->valid()) {
            throw new OperationException(
                sprintf('Entry "%s" has subordinate entries and cannot be deleted.', $dn->toString()),
                ResultCode::NOT_ALLOWED_ON_NON_LEAF,
            );
        }

        unset($this->entries[$this->normalise($dn)]);
    }

    public function update(UpdateCommand $command): void
    {
        $entry = $this->get($command->dn);

        if ($entry === null) {
            throw new OperationException(
                sprintf('No such object: %s', $command->dn->toString()),
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        foreach ($command->changes as $change) {
            $attribute = $change->getAttribute();
            $attrName = $attribute->getName();
            $values = $attribute->getValues();

            switch ($change->getType()) {
                case Change::TYPE_ADD:
                    $existing = $entry->get($attrName);
                    if ($existing !== null) {
                        $entry->get($attrName)?->add(...$values);
                    } else {
                        $entry->add($attribute);
                    }
                    break;

                case Change::TYPE_DELETE:
                    if (count($values) === 0) {
                        $entry->reset($attrName);
                    } else {
                        $entry->get($attrName)?->remove(...$values);
                    }
                    break;

                case Change::TYPE_REPLACE:
                    if (count($values) === 0) {
                        $entry->reset($attrName);
                    } else {
                        $entry->set($attribute);
                    }
                    break;
            }
        }
    }

    public function move(MoveCommand $command): void
    {
        $dn = $command->dn;
        $entry = $this->get($dn);

        if ($entry === null) {
            throw new OperationException(
                sprintf('No such object: %s', $dn->toString()),
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $parent = $command->newParent ?? $dn->getParent();
        $newDnString = $parent !== null
            ? $command->newRdn->toString() . ',' . $parent->toString()
            : $command->newRdn->toString();

        $newDn = new Dn($newDnString);
        $newEntry = new Entry($newDn, ...$entry->getAttributes());

        if ($command->deleteOldRdn) {
            $oldRdn = $dn->getRdn();
            $newEntry->get($oldRdn->getName())?->remove($oldRdn->getValue());
        }

        $rdnName = $command->newRdn->getName();
        $rdnValue = $command->newRdn->getValue();
        $existing = $newEntry->get($rdnName);
        if ($existing !== null) {
            if (!$existing->has($rdnValue)) {
                $existing->add($rdnValue);
            }
        } else {
            $newEntry->set(new Attribute($rdnName, $rdnValue));
        }

        $this->delete(new DeleteCommand($dn));
        $this->add(new AddCommand($newEntry));
    }
}
