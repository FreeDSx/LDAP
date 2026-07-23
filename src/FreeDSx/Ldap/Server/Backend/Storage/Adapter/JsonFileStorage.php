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
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\FileChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Logging\ExceptionLogging;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;

/**
 * JSON-file storage; the container picks forPcntl()/forSwoole() locking from JsonStorageConfig. Reads are lock-free; writes go through atomic() which loads, mutates, and rewrites the file under lock.
 *
 * File format: { "cn=x,dc=y": { "dn": "cn=x,dc=y", "attributes": { "cn": ["x"] } } }
 *
 * @internal built from JsonStorageConfig via ServerOptions::setStorageConfig()
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class JsonFileStorage implements EntryStorageInterface, ChangeJournalingInterface
{
    use ArrayEntryStorageTrait;
    use ChangeJournalingTrait;

    private const JOURNAL_SUFFIX = '.journal.jsonl';

    private const SEQ_SUFFIX = '.journal.seq';

    /**
     * @var array<string, Entry>|null
     */
    private ?array $cache = null;

    private int $cacheMtime = 0;

    private function __construct(
        private readonly string $filePath,
        private readonly StorageLockInterface $lock,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    public static function forPcntl(
        string $filePath,
        ?StorageLockInterface $lock = null,
        ?LoggerInterface $logger = null,
    ): self {
        return new self(
            $filePath,
            $lock ?? new FileLock($filePath),
            $logger ?? new NullLogger(),
        );
    }

    public static function forSwoole(
        string $filePath,
        ?StorageLockInterface $lock = null,
        ?LoggerInterface $logger = null,
    ): self {
        return new self(
            $filePath,
            $lock ?? new CoroutineLock($filePath),
            $logger ?? new NullLogger(),
        );
    }

    public function find(Dn $dn): ?Entry
    {
        return $this->read()[$dn->normalize()->toString()] ?? null;
    }

    public function exists(Dn $dn): bool
    {
        return isset($this->read()[$dn->normalize()->toString()]);
    }

    public function list(StorageListOptions $options): EntryStream
    {
        return $this->listFromArray(
            $options,
            $this->read(),
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
            unset($data[$dn->normalize()->toString()]);

            return $this->encodeContents($data);
        });
    }

    public function atomic(callable $operation): void
    {
        $buffer = $this->newBuffer([]);

        $this->withMutation(
            function (string $contents) use ($operation, &$buffer): string {
                $buffer = $this->newBuffer($this->decodeContents($contents));
                $operation($buffer);

                return $this->encodeContents($buffer->getData());
            },
            // Flush after the data is committed so a failed write records nothing; the shared lock is still held,
            // so the journal append re-enters it rather than deadlocking.
            function () use (&$buffer): void {
                foreach ($buffer->getPendingChanges() as $change) {
                    $this->flushChange($change);
                }
            },
        );
    }

    public function namingContexts(): array
    {
        return $this->namingContextsFromArray($this->read());
    }

    protected function buildJournal(ChangeJournalConfig $config): ChangeJournalInterface
    {
        return new FileChangeJournal(
            $this->lock,
            $this->filePath . self::JOURNAL_SUFFIX,
            $this->filePath . self::SEQ_SUFFIX,
            $config->origin,
        );
    }

    /**
     * Append a committed change to the journal, logging rather than raising a best-effort journal failure so an
     * already-committed entry write is never reported as failed; sync reconciles the lost record via the present phase.
     */
    private function flushChange(PendingChange $change): void
    {
        try {
            $this->appendChange($change);
        } catch (Throwable $e) {
            $this->logger->error(
                'Failed to append a committed change to the file change journal.',
                ExceptionLogging::makeLogContext($e),
            );
        }
    }

    /**
     * @param callable(string): string $mutation
     * @param ?callable(): void $afterCommit
     */
    private function withMutation(
        callable $mutation,
        ?callable $afterCommit = null,
    ): void {
        try {
            $this->lock->withLock(
                $mutation,
                $afterCommit,
            );
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
            $attributes[$attribute->getDescription()] = array_values($attribute->getValues());
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
                    ...$stringValues,
                );
            }
        }

        return new Entry(
            new Dn($dn),
            ...$attributes,
        );
    }

    /**
     * @param array<string, mixed> $data
     */
    private function newBuffer(array $data): JsonEntryBuffer
    {
        return new JsonEntryBuffer(
            $data,
            $this->arrayToEntry(...),
            $this->entryToArray(...),
        );
    }
}
