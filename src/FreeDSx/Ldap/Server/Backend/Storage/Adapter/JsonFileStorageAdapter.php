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
use FreeDSx\Ldap\Server\Backend\SearchContext;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\CoroutineLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\FileLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\StorageLockInterface;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WritableBackendTrait;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use Generator;

/**
 * A file-backed storage adapter that persists the directory as a JSON file.
 *
 * Use the named constructors to select the correct locking strategy:
 *
 *   JsonFileStorageAdapter::forPcntl('/path/to/file.json')
 *   JsonFileStorageAdapter::forSwoole('/path/to/file.json')
 *
 * JSON format:
 * {
 *   "cn=admin,dc=example,dc=com": {
 *     "dn": "cn=admin,dc=example,dc=com",
 *     "attributes": {
 *       "cn": ["admin"],
 *       "userPassword": ["{SHA}..."]
 *     }
 *   }
 * }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class JsonFileStorageAdapter implements WritableLdapBackendInterface
{
    use StorageAdapterTrait;
    use WritableBackendTrait;

    /**
     * @var array<string, Entry>|null
     */
    private ?array $cache = null;

    private int $cacheMtime = 0;

    private function __construct(
        private readonly string $filePath,
        private readonly StorageLockInterface $lock,
    ) {
    }

    public static function forPcntl(
        string $filePath,
        ?StorageLockInterface $lock = null,
    ): self {
        return new self(
            $filePath,
            $lock ?? new FileLock($filePath)
        );
    }

    public static function forSwoole(
        string $filePath,
        ?StorageLockInterface $lock = null,
    ): self {
        return new self(
            $filePath,
            $lock ?? new CoroutineLock($filePath)
        );
    }

    public function get(Dn $dn): ?Entry
    {
        return $this->read()[$this->normalise($dn)] ?? null;
    }

    public function search(SearchContext $context): Generator
    {
        $normBase = $this->normalise($context->baseDn);

        foreach ($this->read() as $normDn => $entry) {
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
        $this->withMutation(
            fn(string $contents): string => $this->executeAdd(
                $contents,
                $command
            )
        );
    }

    public function delete(DeleteCommand $command): void
    {
        $this->withMutation(
            fn(string $contents): string => $this->executeDelete(
                $contents,
                $command
            )
        );
    }

    public function update(UpdateCommand $command): void
    {
        $this->withMutation(
            fn(string $contents): string => $this->executeUpdate(
                $contents,
                $command
            )
        );
    }

    public function move(MoveCommand $command): void
    {
        $this->withMutation(
            fn(string $contents): string => $this->executeMove(
                $contents,
                $command
            )
        );
    }

    /**
     * @param callable(string): string $mutation
     */
    private function withMutation(callable $mutation): void
    {
        try {
            $this->lock->withLock($mutation);
        } finally {
            $this->cache = null;
        }
    }

    /**
     * @throws OperationException
     */
    private function executeAdd(
        string $contents,
        AddCommand $command,
    ): string {
        $data = $this->decodeContents($contents);
        $normDn = $this->normalise($command->entry->getDn());

        if (isset($data[$normDn])) {
            throw new OperationException(
                sprintf('Entry already exists: %s', $command->entry->getDn()->toString()),
                ResultCode::ENTRY_ALREADY_EXISTS,
            );
        }

        $data[$normDn] = $this->entryToArray($command->entry);

        return $this->encodeContents($data);
    }

    /**
     * @throws OperationException
     */
    private function executeDelete(
        string $contents,
        DeleteCommand $command,
    ): string {
        $data = $this->decodeContents($contents);
        $normDn = $this->normalise($command->dn);

        foreach (array_keys($data) as $key) {
            if ($this->isInScope($key, $normDn, SearchRequest::SCOPE_SINGLE_LEVEL)) {
                throw new OperationException(
                    sprintf('Entry "%s" has subordinate entries and cannot be deleted.', $command->dn->toString()),
                    ResultCode::NOT_ALLOWED_ON_NON_LEAF,
                );
            }
        }

        unset($data[$normDn]);

        return $this->encodeContents($data);
    }

    /**
     * @throws OperationException
     */
    private function executeUpdate(
        string $contents,
        UpdateCommand $command,
    ): string {
        $data = $this->decodeContents($contents);
        $normDn = $this->normalise($command->dn);

        if (!isset($data[$normDn])) {
            throw new OperationException(
                sprintf('No such object: %s', $command->dn->toString()),
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $entry = $this->arrayToEntry($data[$normDn]);

        foreach ($command->changes as $change) {
            $attribute = $change->getAttribute();
            $attrName = $attribute->getName();
            $values = $attribute->getValues();

            switch ($change->getType()) {
                case Change::TYPE_ADD:
                    $existing = $entry->get($attrName);
                    if ($existing !== null) {
                        $existing->add(...$values);
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

        $data[$normDn] = $this->entryToArray($entry);

        return $this->encodeContents($data);
    }

    /**
     * @throws OperationException
     */
    private function executeMove(
        string $contents,
        MoveCommand $command,
    ): string {
        $data = $this->decodeContents($contents);
        $normOld = $this->normalise($command->dn);

        if (!isset($data[$normOld])) {
            throw new OperationException(
                sprintf('No such object: %s', $command->dn->toString()),
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $entry = $this->arrayToEntry($data[$normOld]);

        $parent = $command->newParent ?? $command->dn->getParent();
        $newDnString = $parent !== null
            ? $command->newRdn->toString() . ',' . $parent->toString()
            : $command->newRdn->toString();

        $newDn = new Dn($newDnString);
        $newEntry = new Entry($newDn, ...$entry->getAttributes());

        if ($command->deleteOldRdn) {
            $oldRdn = $command->dn->getRdn();
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

        unset($data[$normOld]);
        $data[$this->normalise($newDn)] = $this->entryToArray($newEntry);

        return $this->encodeContents($data);
    }

    /**
     * @return array<string, Entry>
     */
    private function read(): array
    {
        if (!file_exists($this->filePath)) {
            $this->cache = [];
            $this->cacheMtime = 0;

            return $this->cache;
        }

        $mtime = (int) filemtime($this->filePath);

        if ($this->cache !== null && $this->cacheMtime === $mtime) {
            return $this->cache;
        }

        $contents = file_get_contents($this->filePath);

        if ($contents === false || $contents === '') {
            $this->cache = [];
            $this->cacheMtime = $mtime;

            return $this->cache;
        }

        $entries = [];
        foreach ($this->decodeContents($contents) as $normDn => $data) {
            $entries[$normDn] = $this->arrayToEntry($data);
        }

        $this->cache = $entries;
        $this->cacheMtime = $mtime;

        return $this->cache;
    }

    /**
     * @return array{dn: string, attributes: array<string, list<string>>}
     */
    private function entryToArray(Entry $entry): array
    {
        $attributes = [];
        foreach ($entry->getAttributes() as $attribute) {
            $attributes[$attribute->getName()] = array_values($attribute->getValues());
        }

        return [
            'dn' => $entry->getDn()->toString(),
            'attributes' => $attributes,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function decodeContents(string $contents): array
    {
        if ($contents === '') {
            return [];
        }

        $raw = json_decode($contents, true);

        if (!is_array($raw)) {
            return [];
        }

        return array_filter($raw, function ($key) {
            return is_string($key);
        }, ARRAY_FILTER_USE_KEY);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function encodeContents(array $data): string
    {
        return json_encode(
            $data,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE
        ) ?: '{}';
    }

    private function arrayToEntry(mixed $data): Entry
    {
        if (!is_array($data)) {
            return new Entry(new Dn(''));
        }

        $dn = isset($data['dn']) && is_string($data['dn']) ? $data['dn'] : '';

        $attributes = [];
        if (isset($data['attributes']) && is_array($data['attributes'])) {
            foreach ($data['attributes'] as $name => $values) {
                if (!is_string($name) || !is_array($values)) {
                    continue;
                }
                $stringValues = [];
                foreach ($values as $v) {
                    if (is_string($v)) {
                        $stringValues[] = $v;
                    }
                }
                $attributes[] = new Attribute(
                    $name,
                    ...$stringValues
                );
            }
        }

        return new Entry(
            new Dn($dn),
            ...$attributes
        );
    }
}
