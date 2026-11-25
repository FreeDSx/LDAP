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

namespace FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\JournalLapsedException;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeScope;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;

use function array_pop;
use function array_push;
use function array_reverse;

/**
 * Tails the change journal for a refreshAndPersist consumer, yielding changes until it cancels or disconnects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SyncPersistStreamer
{
    /**
     * Seconds between journal polls; also bounds change-delivery latency and dead-peer detection.
     */
    public const DEFAULT_POLL_INTERVAL = 1.0;

    public function __construct(
        private ReadEntryInterface $entries,
        private SyncResultProjector $projector,
        private ChangeStream $stream,
        private LinkedAttributes $linked,
        private SleeperInterface $sleeper,
        private float $pollInterval = self::DEFAULT_POLL_INTERVAL,
        private SyncResultBatcher $batcher = new SyncResultBatcher(),
    ) {}

    /**
     * The net effect of journal changes after one sequence and through another, each sent after the entries it needs.
     *
     * @param int $throughSeq The seq the cookie sent after these results claims.
     * @return iterable<SyncResult>
     *
     * @throws JournalLapsedException
     */
    public function projectSince(
        int $sinceSeq,
        int $throughSeq,
        SearchRequest $request,
        TokenInterface $token,
    ): iterable {
        $scope = $this->scopeFor($request);
        $window = $this->windowOf(
            $sinceSeq,
            $throughSeq,
            $scope,
            $token,
        );

        foreach ($this->stream->since($sinceSeq, $scope, $throughSeq) as $record) {
            $change = $record->change;

            if (!$window->isLatest($record) || $window->wasSent($change->entryUuid)) {
                continue;
            }

            $results = $this->resultsFor(
                $change,
                $window,
                $scope,
                $request,
                $token,
            );

            foreach ($results as $result) {
                yield $result;
            }
        }
    }

    /**
     * The persist phase: yields each change as it lands, advancing the cookie, until cancel or disconnect.
     *
     * The writer polls the queue and offers any abandon/cancel into the shared token, which this loop reads.
     *
     * @return Generator<LdapMessageResponse>
     */
    public function stream(
        int $startSeq,
        SearchRequest $request,
        TokenInterface $token,
        int $messageId,
        Cancellation $cancellation,
    ): Generator {
        $lastSeq = $startSeq;
        $origin = $this->stream->origin();
        $generation = $this->stream->generation();
        $contentKey = SyncCookie::contentKey($request);

        while (true) {
            $latestSeq = $this->stream->latestSeq();

            // A trim past the consumer's position would silently drop changes: force a full re-sync instead.
            if ($latestSeq > $lastSeq && !$this->stream->retainsSince($lastSeq)) {
                yield $this->refreshRequired($messageId);

                return;
            }

            if ($latestSeq > $lastSeq) {
                try {
                    yield from $this->pushChanges(
                        $lastSeq,
                        $latestSeq,
                        $request,
                        $token,
                        $messageId,
                    );
                } catch (JournalLapsedException) {
                    yield $this->refreshRequired($messageId);

                    return;
                }
                $lastSeq = $latestSeq;
            }

            // Advances the client cookie, and doubles as a keepalive that surfaces a dead peer on the next poll.
            yield new LdapMessageResponse(
                $messageId,
                new SyncNewCookie((new SyncCookie(
                    $origin,
                    $lastSeq,
                    $contentKey,
                    $generation,
                ))->encode()),
            );

            $signal = $cancellation->signal();

            if ($signal !== null) {
                // Abandon carries no response (RFC 4511 §4.11); only a Cancel gets an acknowledged close.
                if ($cancellation->isCanceled()) {
                    yield from $this->terminal(
                        $signal->getMessageId(),
                        $messageId,
                        $origin,
                        $lastSeq,
                        $contentKey,
                        $generation,
                    );
                }

                return;
            }

            $this->sleeper->sleep($this->pollInterval);
        }
    }

    /**
     * The responses as they are, ended by e-syncRefreshRequired if the journal no longer covers what they read.
     *
     * @param Generator<LdapMessageResponse> $responses
     *
     * @return Generator<LdapMessageResponse>
     */
    public function endOnLapse(
        Generator $responses,
        int $messageId,
    ): Generator {
        try {
            yield from $responses;
        } catch (JournalLapsedException) {
            yield $this->refreshRequired($messageId);
        }
    }

    /**
     * @return Generator<LdapMessageResponse>
     */
    private function pushChanges(
        int $sinceSeq,
        int $throughSeq,
        SearchRequest $request,
        TokenInterface $token,
        int $messageId,
    ): Generator {
        yield from $this->batcher->batch(
            $this->projectSince(
                $sinceSeq,
                $throughSeq,
                $request,
                $token,
            ),
            $messageId,
        );
    }

    /**
     * @throws JournalLapsedException
     */
    private function windowOf(
        int $sinceSeq,
        int $throughSeq,
        ChangeScope $scope,
        TokenInterface $token,
    ): ChangeWindow {
        $window = new ChangeWindow(
            $scope,
            fn(Dn $dn): bool => $this->projector->isVisibleAt(
                $token,
                $dn,
            ),
        );

        foreach ($this->stream->since($sinceSeq, $scope, $throughSeq) as $record) {
            $window->record($record);
        }

        return $window;
    }

    /**
     * @return iterable<SyncResult>
     */
    private function resultsFor(
        PendingChange $change,
        ChangeWindow $window,
        ChangeScope $scope,
        SearchRequest $request,
        TokenInterface $token,
    ): iterable {
        if ($change->changeType !== ChangeType::Delete) {
            return $this->afterDependencies(
                $change->entryUuid,
                $window,
                $scope,
                $request,
                $token,
            );
        }

        $result = $this->projector->projectDeleted(
            $change,
            $window->lastVisible($change->entryUuid),
            $window->hasEarlierChange($change->entryUuid),
            $request,
        );

        return $result === null
            ? []
            : [$result];
    }

    /**
     * The entry's result, preceded by those of the unsent window entries it depends on, each sent once.
     *
     * @return Generator<SyncResult>
     */
    private function afterDependencies(
        string $entryUuid,
        ChangeWindow $window,
        ChangeScope $scope,
        SearchRequest $request,
        TokenInterface $token,
    ): Generator {
        $pending = [$entryUuid];

        // A result waits on the stack beneath the entries it depends on, which are sent first.
        while (($next = array_pop($pending)) !== null) {
            if ($next instanceof SyncResult) {
                $window->release();

                yield $next;

                continue;
            }

            array_push(
                $pending,
                ...$this->visit(
                    $next,
                    $window,
                    $scope,
                    $request,
                    $token,
                ),
            );
        }
    }

    /**
     * The entry's result followed by the unsent window entries it depends on, or nothing when it was read already.
     *
     * @return list<SyncResult|string>
     */
    private function visit(
        string $entryUuid,
        ChangeWindow $window,
        ChangeScope $scope,
        SearchRequest $request,
        TokenInterface $token,
    ): array {
        if ($window->wasSent($entryUuid)) {
            return [];
        }
        $window->markSent($entryUuid);

        $result = $this->fetchAndProject(
            $entryUuid,
            $window,
            $scope,
            $request,
            $token,
        );

        if ($result === null) {
            return [];
        }
        // Awaited before its own links are read, which can lead back beneath it.
        $window->await($entryUuid);

        return [
            $result,
            ...array_reverse($this->dependenciesOf(
                $result,
                $window,
            )),
        ];
    }

    /**
     * The unsent window entries now holding the parent DN an entry is sent under or a DN its links name.
     *
     * @return list<string>
     */
    private function dependenciesOf(
        SyncResult $result,
        ChangeWindow $window,
    ): array {
        if ($result->control->isDelete() || !$window->hasUnsentHolders()) {
            return [];
        }
        $dependencies = [];

        foreach ($this->namesNeededBy($result->entry->getEntry()) as $dn) {
            $holder = $window->unsentHolderOf($dn);

            if ($holder !== null) {
                $dependencies[] = $holder;
            }
        }

        return $dependencies;
    }

    /**
     * The DNs a consumer must hold before it can store the entry: its parent and those its links name.
     *
     * @return Generator<string>
     */
    private function namesNeededBy(Entry $entry): Generator
    {
        $parent = Dn::canonicalParent($entry->getDn()->normalizedString());

        if ($parent !== '') {
            yield $parent;
        }

        foreach ($this->linked->valuesOf($entry) as $name => $values) {
            foreach ($values as $value) {
                yield $this->linked->targetOf(
                    $name,
                    $value,
                )->name;
            }
        }
    }

    /**
     * Read by entryUUID, so it is the entry the change is about, judged against the content where it lives now.
     */
    private function fetchAndProject(
        string $entryUuid,
        ChangeWindow $window,
        ChangeScope $scope,
        SearchRequest $request,
        TokenInterface $token,
    ): ?SyncResult {
        $lastVisible = $window->lastVisible($entryUuid);
        $entry = $this->entries->findByUuid(
            $entryUuid,
            $this->projector->fetchProjectionFor($request),
        );

        // Deleted since, and announced now because a later delete judged by its pre-image alone could be withheld.
        if ($entry === null) {
            return $this->projector->projectLeft(
                $entryUuid,
                $lastVisible,
            );
        }

        // RFC 4533 §4.1 wants an entry that left the content deleted rather than sent from where it went.
        if (!$scope->contains($entry->getDn())) {
            return $this->projector->projectLeft(
                $entryUuid,
                $lastVisible,
            );
        }

        return $this->projector->projectFetched(
            $entry,
            $entryUuid,
            $window->isAdded($entryUuid),
            $lastVisible,
            $request,
            $token,
        );
    }

    private function scopeFor(SearchRequest $request): ChangeScope
    {
        $baseDn = $request->getBaseDn() ?? new Dn('');

        return match ($request->getScope()) {
            SearchRequest::SCOPE_BASE_OBJECT => ChangeScope::baseObject($baseDn),
            SearchRequest::SCOPE_SINGLE_LEVEL => ChangeScope::oneLevel($baseDn),
            default => ChangeScope::wholeSubtree($baseDn),
        };
    }

    /**
     * @return Generator<LdapMessageResponse>
     */
    private function terminal(
        int $cancelMessageId,
        int $messageId,
        ReplicaId $origin,
        int $lastSeq,
        string $contentKey,
        string $generation,
    ): Generator {
        yield new LdapMessageResponse(
            $messageId,
            new SearchResultDone(ResultCode::CANCELED),
            new SyncDoneControl(
                (new SyncCookie(
                    $origin,
                    $lastSeq,
                    $contentKey,
                    $generation,
                ))->encode(),
                true,
            ),
        );
        yield new LdapMessageResponse(
            $cancelMessageId,
            new ExtendedResponse(new LdapResult(ResultCode::SUCCESS)),
        );
    }

    /**
     * RFC 4533 §2.5: a cookie here would mean an incremental refresh is enough, so the pruned window must be
     * signalled by omitting it, which asks for the full refresh the consumer actually needs.
     */
    private function refreshRequired(int $messageId): LdapMessageResponse
    {
        return new LdapMessageResponse(
            $messageId,
            new SearchResultDone(ResultCode::SYNCHRONIZATION_REFRESH_REQUIRED),
            new SyncDoneControl(
                null,
                true,
            ),
        );
    }
}
