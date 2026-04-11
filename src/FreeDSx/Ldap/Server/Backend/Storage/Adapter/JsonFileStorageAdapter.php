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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\CoroutineLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\FileLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\StorageLockInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\WriteEntryOperationHandler;
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
        private readonly WriteEntryOperationHandler $entryHandler = new WriteEntryOperationHandler(),
    ) {
    }

    public static function forPcntl(
        string $filePath,
        ?StorageLockInterface $lock = null,
    ): self {
        return new self(
            $filePath,
            $lock ?? new FileLock($filePath),
        );
    }

    public static function forSwoole(
        string $filePath,
        ?StorageLockInterface $lock = null,
    ): self {
        return new self(
            $filePath,
            $lock ?? new CoroutineLock($filePath),
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
        $this->withMutation(function (string $contents) use ($command): string {
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
        });
    }

    /**
     * @throws OperationException
     */
    public function delete(DeleteCommand $command): void
    {
        $this->withMutation(function (string $contents) use ($command): string {
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
        });
    }

    /**
     * @throws OperationException
     */
    public function update(UpdateCommand $command): void
    {
        $this->withMutation(function (string $contents) use ($command): string {
            $data = $this->decodeContents($contents);
            $normDn = $this->normalise($command->dn);

            if (!isset($data[$normDn])) {
                throw new OperationException(
                    sprintf('No such object: %s', $command->dn->toString()),
                    ResultCode::NO_SUCH_OBJECT,
                );
            }

            $entry = $this->entryHandler->apply(
                $this->arrayToEntry($data[$normDn]),
                $command,
            );
            $data[$normDn] = $this->entryToArray($entry);

            return $this->encodeContents($data);
        });
    }

    /**
     * @throws OperationException
     */
    public function move(MoveCommand $command): void
    {
        $this->withMutation(function (string $contents) use ($command): string {
            $data = $this->decodeContents($contents);
            $normOld = $this->normalise($command->dn);

            if (!isset($data[$normOld])) {
                throw new OperationException(
                    sprintf('No such object: %s', $command->dn->toString()),
                    ResultCode::NO_SUCH_OBJECT,
                );
            }

            $newEntry = $this->entryHandler->apply(
                $this->arrayToEntry($data[$normOld]),
                $command,
            );
            unset($data[$normOld]);
            $data[$this->normalise($newEntry->getDn())] = $this->entryToArray($newEntry);

            return $this->encodeContents($data);
        });
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
