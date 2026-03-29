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
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\SearchContext;
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
 * Safe for use with the PCNTL server runner: write operations are serialised
 * using flock(LOCK_EX), so concurrent child processes do not corrupt the file.
 * An in-memory cache is invalidated via filemtime checks to avoid re-reading
 * the file on every read operation within a single forked process.
 *
 * Note: when used with the Swoole server runner, standard flock/fread calls
 * are blocking and will stall the event loop. Use the InMemoryStorageAdapter
 * with Swoole, or a Swoole-coroutine-aware file I/O layer instead.
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

    public function __construct(private readonly string $filePath)
    {
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
        $entry = $command->entry;
        $this->withLock(function (array $data) use ($entry): array {
            $normDn = $this->normalise($entry->getDn());

            if (isset($data[$normDn])) {
                throw new OperationException(
                    sprintf('Entry already exists: %s', $entry->getDn()->toString()),
                    ResultCode::ENTRY_ALREADY_EXISTS,
                );
            }

            $data[$normDn] = $this->entryToArray($entry);

            return $data;
        });
    }

    public function delete(DeleteCommand $command): void
    {
        $normDn = $this->normalise($command->dn);
        $this->withLock(function (array $data) use ($normDn, $command): array {
            foreach (array_keys($data) as $key) {
                if ($this->isInScope($key, $normDn, SearchRequest::SCOPE_SINGLE_LEVEL)) {
                    throw new OperationException(
                        sprintf('Entry "%s" has subordinate entries and cannot be deleted.', $command->dn->toString()),
                        ResultCode::NOT_ALLOWED_ON_NON_LEAF,
                    );
                }
            }

            unset($data[$normDn]);

            return $data;
        });
    }

    public function update(UpdateCommand $command): void
    {
        $normDn = $this->normalise($command->dn);
        $this->withLock(function (array $data) use ($normDn, $command): array {
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

            return $data;
        });
    }

    public function move(MoveCommand $command): void
    {
        $normOld = $this->normalise($command->dn);
        $this->withLock(function (array $data) use ($normOld, $command): array {
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

            return $data;
        });
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

        $raw = json_decode($contents, true);

        if (!is_array($raw)) {
            $this->cache = [];
            $this->cacheMtime = $mtime;

            return $this->cache;
        }

        $entries = [];
        foreach ($raw as $normDn => $data) {
            if (!is_string($normDn)) {
                continue;
            }
            $entries[$normDn] = $this->arrayToEntry($data);
        }

        $this->cache = $entries;
        $this->cacheMtime = $mtime;

        return $this->cache;
    }

    /**
     * Open the file with an exclusive lock, call $mutation with the current
     * data array, write back the result, then release the lock.
     *
     * @param callable(array<string, mixed>): array<string, mixed> $mutation
     */
    private function withLock(callable $mutation): void
    {
        $handle = fopen($this->filePath, 'c+');

        if ($handle === false) {
            throw new RuntimeException(sprintf(
                'Unable to open storage file: %s',
                $this->filePath
            ));
        }

        if (!flock($handle, LOCK_EX)) {
            fclose($handle);
            throw new RuntimeException(sprintf(
                'Unable to acquire exclusive lock on storage file: %s',
                $this->filePath
            ));
        }

        try {
            $data = $mutation($this->readFromHandle($handle));
            $this->writeToHandle($handle, $data);
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
            $this->cache = null;
        }
    }

    /**
     * Read and decode the current JSON contents from an open file handle.
     *
     * @param resource $handle
     * @return array<string, mixed>
     */
    private function readFromHandle(mixed $handle): array
    {
        $size = fstat($handle)['size'] ?? 0;
        $contents = $size > 0 ? fread($handle, $size) : '';
        $rawDecoded = ($contents !== '' && $contents !== false)
            ? json_decode($contents, true)
            : null;

        if (!is_array($rawDecoded)) {
            return [];
        }

        $data = [];
        foreach ($rawDecoded as $key => $value) {
            if (is_string($key)) {
                $data[$key] = $value;
            }
        }

        return $data;
    }

    /**
     * Encode and write data back to an open file handle, truncating first.
     *
     * @param resource $handle
     * @param array<string, mixed> $data
     */
    private function writeToHandle(
        mixed $handle,
        array $data,
    ): void {
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) ?: '{}');
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
                $attributes[] = new Attribute($name, ...$stringValues);
            }
        }

        return new Entry(
            new Dn($dn),
            ...$attributes
        );
    }
}
