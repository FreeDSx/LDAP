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

namespace Tests\Support\FreeDSx\Ldap\Sync\Convergence;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Ldif\LdifChangeRecord;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSyncHandler;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\Rule\OperationRule;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\AccessControl\Target\Target;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ListEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\Write\Replay\WriteRequestReplayer;
use FreeDSx\Ldap\Server\Config\Replication\ProviderConfig;
use FreeDSx\Ldap\Server\Config\ReplicationConfig;
use FreeDSx\Ldap\Server\Config\Storage\StorageConfigInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\ServerOptions;
use FreeDSx\Ldap\Sync\Provider\SyncPersistStreamer;
use FreeDSx\Ldap\Sync\Provider\SyncResultProjector;
use Generator;
use Tests\Support\FreeDSx\Ldap\Server\Clock\CallbackSleeper;

use function strtolower;

use const PHP_INT_MAX;

/**
 * A provider in this process, writing through the server's own pipeline and never waiting between polls.
 */
final class ConvergenceProvider
{
    public const BASE = 'dc=example,dc=com';

    public const HIDDEN = 'ou=hidden,dc=example,dc=com';

    private const SYNC_IDENTITY = 'cn=sync,dc=example,dc=com';

    private int $messageId = 0;

    /**
     * @var array<string, true> the entries that sat in the hidden subtree at some point, keyed by lowercased entryUUID
     */
    private array $everHidden = [];

    /**
     * @var array<string, true> the entries a write moved while the sync was reading, keyed by lowercased entryUUID
     */
    private array $movedMidFetch = [];

    private function __construct(
        private readonly WriteRequestReplayer $replayer,
        private readonly ListEntryInterface $lister,
        private readonly DriftingEntryReader $reader,
        private readonly ChangeStream $journal,
        private readonly ServerSyncHandler $handler,
    ) {}

    /**
     * A provider on the storage the replica uses, as the two keep group links the same way only then.
     */
    public static function on(StorageConfigInterface $storage): self
    {
        $options = self::options($storage);
        $container = Container::forServer($options);
        $reader = new DriftingEntryReader($container->get(ReadEntryInterface::class));
        $journal = new ChangeStream($container->get(ChangeJournalInterface::class));

        return new self(
            $container->get(WriteRequestReplayer::class),
            $container->get(ListEntryInterface::class),
            $reader,
            $journal,
            self::syncHandler(
                $container,
                $journal,
                $reader,
            ),
        );
    }

    /**
     * Applies the write, answering whether the server accepted it.
     */
    public function write(RequestInterface $request): bool
    {
        try {
            $this->replayer->apply([new LdifChangeRecord($request)]);
        } catch (OperationException) {
            return false;
        }
        $this->noteHidden();

        return true;
    }

    /**
     * Applies the write just before the sync's given fetch of a live entry.
     */
    public function writeBeforeFetch(
        int $fetch,
        RequestInterface $request,
    ): void {
        $this->reader->beforeFetch(
            $fetch,
            function () use ($request): void {
                $moved = $request instanceof ModifyDnRequest
                    ? $this->uuidsUnder($request->getDn())
                    : [];

                if (!$this->write($request)) {
                    return;
                }

                foreach ($moved as $uuid) {
                    $this->movedMidFetch[$uuid] = true;
                }
            },
        );
    }

    /**
     * Drops a write whose fetch never came.
     */
    public function cancelDrift(): void
    {
        $this->reader->disarm();
    }

    /**
     * The messages a refreshAndPersist sync from the cookie sends, polling for changes each time it is resumed.
     *
     * @return Generator<LdapMessageResponse>
     */
    public function sync(?string $cookie): Generator
    {
        $message = new LdapMessageRequest(
            ++$this->messageId,
            (new SyncRequest())
                ->base(self::BASE)
                ->useSubtreeScope(),
            new SyncRequestControl(
                SyncRequestControl::MODE_REFRESH_AND_PERSIST,
                $cookie,
            ),
        );

        return $this->handler
            ->handleRequest(
                $message,
                new BindToken(AuthzId::fromDn(new Dn(self::SYNC_IDENTITY))),
            )
            ->generator();
    }

    /**
     * The sequence of the last change written, which a replica that caught up holds in its checkpoint.
     */
    public function latestSeq(): int
    {
        return $this->journal->latestSeq();
    }

    /**
     * Every entry stored, including the hidden ones a write may target.
     *
     * @return list<Entry>
     */
    public function entries(): array
    {
        $options = StorageListOptions::matchAll(
            new Dn(''),
            subtree: true,
        );
        $entries = [];

        foreach ($this->lister->list($options)->entries() as $entry) {
            $entries[] = $entry;
        }

        return $entries;
    }

    public function snapshot(): DirectorySnapshot
    {
        return DirectorySnapshot::visibleIn($this->lister);
    }

    /**
     * The entries that sat in the hidden subtree at some point, keyed by lowercased entryUUID.
     *
     * @return array<string, true>
     */
    public function everHidden(): array
    {
        return $this->everHidden;
    }

    /**
     * The entries a write moved while the sync was reading, keyed by lowercased entryUUID.
     *
     * @return array<string, true>
     */
    public function movedMidFetch(): array
    {
        return $this->movedMidFetch;
    }

    /**
     * The lowercased entryUUIDs of the entry at the DN and everything under it, which a rename of it moves together.
     *
     * @return list<string>
     */
    private function uuidsUnder(Dn $dn): array
    {
        $options = StorageListOptions::matchAll(
            $dn->normalize(),
            subtree: true,
            projection: new EntryProjection(
                [strtolower(AttributeTypeOid::NAME_ENTRY_UUID)],
                linkCap: 0,
            ),
        );
        $uuids = [];

        foreach ($this->lister->list($options)->entries() as $entry) {
            $uuids[] = strtolower($entry->getUuidOrFail());
        }

        return $uuids;
    }

    private function noteHidden(): void
    {
        foreach ($this->entries() as $entry) {
            if (DirectorySnapshot::isHidden($entry->getDn()->normalize())) {
                $this->everHidden[strtolower($entry->getUuidOrFail())] = true;
            }
        }
    }

    private static function options(StorageConfigInterface $storage): ServerOptions
    {
        $options = (new ServerOptions($storage))
            ->setReplicationConfig(ReplicationConfig::forProvider(new ProviderConfig()));

        return $options->setAclRules($options->getAclRules()->prependOperationRules(OperationRule::deny(
            Subject::dn(self::SYNC_IDENTITY),
            Target::subtree(self::HIDDEN),
            OperationType::Search,
            OperationType::Compare,
        )));
    }

    /**
     * Built as the server builds it, with persist allowed and a reader that can drift.
     */
    private static function syncHandler(
        Container $container,
        ChangeStream $journal,
        ReadEntryInterface $reader,
    ): ServerSyncHandler {
        $projector = self::projector($container);

        return new ServerSyncHandler(
            backend: $container->get(ReadBackendInterface::class),
            projector: $projector,
            limits: $container->get(ServerOptions::class)->makeSearchLimits(),
            changeStream: $journal,
            persistStreamer: new SyncPersistStreamer(
                entries: $reader,
                projector: $projector,
                stream: $journal,
                linked: $container->get(LinkedAttributes::class),
                sleeper: new CallbackSleeper(maxTicks: PHP_INT_MAX),
            ),
            persistSupported: true,
        );
    }

    private static function projector(Container $container): SyncResultProjector
    {
        return new SyncResultProjector(
            accessControl: $container->get(AccessControlInterface::class),
            filterEvaluator: $container->get(FilterEvaluatorInterface::class),
            schema: $container->get(ServerOptions::class)->getSchema(),
            linkedLeaves: $container->get(LinkedLeafWitness::class),
            linked: $container->get(LinkedAttributes::class),
        );
    }
}
