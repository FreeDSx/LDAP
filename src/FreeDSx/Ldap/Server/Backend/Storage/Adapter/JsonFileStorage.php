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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\CoroutineLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\FileLock;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\StorageLockInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\ArrayEntryStorageTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support\JsonEntryBuffer;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * JSON-file storage; use forPcntl() / forSwoole() to pick a locking strategy. Reads are lock-free; writes go through atomic() which loads, mutates, and rewrites the file under lock.
 *
 * File format: { "cn=x,dc=y": { "dn": "cn=x,dc=y", "attributes": { "cn": ["x"] } } }
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class JsonFileStorage implements EntryStorageInterface
{
    use ArrayEntryStorageTrait;

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

    public function find(Dn $dn): ?Entry
    {
        return $this->read()[$dn->toString()] ?? null;
    }

    public function exists(Dn $dn): bool
    {
        return isset($this->read()[$dn->toString()]);
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return new EntryStream(
            $this->yieldByScope(
                $this->read(),
                $options->baseDn,
                $options->subtree,
                $options->timeLimit,
            ),
        );
    }

    public function store(Entry $entry): void
    {
        $this->withMutation(function (string $contents) use ($entry): string {
            $data = $this->decodeContents($contents);
            $data[$entry->getDn()->normalize()->toString()] = $this->entryToArray($entry);

            return $this->encodeContents($data);
        });
    }

    public function remove(Dn $dn): void
    {
        $this->withMutation(function (string $contents) use ($dn): string {
            $data = $this->decodeContents($contents);
            unset($data[$dn->toString()]);

            return $this->encodeContents($data);
        });
    }

    public function atomic(callable $operation): void
    {
        $this->withMutation(function (string $contents) use ($operation): string {
            $data = $this->decodeContents($contents);
            $buffer = new JsonEntryBuffer(
                $data,
                $this->arrayToEntry(...),
                $this->entryToArray(...),
            );
            $operation($buffer);

            return $this->encodeContents($buffer->getData());
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
            JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        );
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
