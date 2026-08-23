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
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ReplicaId;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeScope;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Clock\Sleeper\SleeperInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;

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
        private LdapBackendInterface $backend,
        private SyncResultProjector $projector,
        private ChangeStream $stream,
        private SleeperInterface $sleeper,
        private float $pollInterval = self::DEFAULT_POLL_INTERVAL,
        private SyncResultBatcher $batcher = new SyncResultBatcher(),
    ) {}

    /**
     * The net effect of journal changes since a sequence, as sync results (adds and deletes).
     *
     * @return iterable<SyncResult>
     */
    public function projectSince(
        int $sinceSeq,
        SearchRequest $request,
        TokenInterface $token,
    ): iterable {
        $scope = $this->scopeFor($request);
        $netByUuid = [];

        foreach ($this->stream->since($sinceSeq, $scope) as $record) {
            $netByUuid[$record->change->entryUuid] = $record->change;
        }

        foreach ($netByUuid as $change) {
            $result = match (true) {
                $change->changeType === ChangeType::Delete => $this->projector->projectDeleted(
                    $change,
                    $request,
                    $token,
                ),
                // Left the content, so RFC 4533 §4.1 wants it deleted rather than sent from where it went.
                !$scope->contains($change->dn) => $this->fetchAndProjectMovedOut(
                    $change,
                    $token,
                ),
                default => $this->fetchAndProject(
                    $change,
                    $request,
                    $token,
                ),
            };

            if ($result !== null) {
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
        $contentKey = SyncCookie::contentKey($request);

        while (true) {
            $latestSeq = $this->stream->latestSeq();

            // A trim past the consumer's position would silently drop changes: force a full re-sync instead.
            if ($latestSeq > $lastSeq && !$this->stream->retainsSince($lastSeq)) {
                yield $this->refreshRequired($messageId);

                return;
            }

            if ($latestSeq > $lastSeq) {
                yield from $this->pushChanges($lastSeq, $request, $token, $messageId);
                $lastSeq = $latestSeq;
            }

            // Advances the client cookie, and doubles as a keepalive that surfaces a dead peer on the next poll.
            yield new LdapMessageResponse(
                $messageId,
                new SyncNewCookie((new SyncCookie($origin, $lastSeq, $contentKey))->encode()),
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
                    );
                }

                return;
            }

            $this->sleeper->sleep($this->pollInterval);
        }
    }

    /**
     * @return Generator<LdapMessageResponse>
     */
    private function pushChanges(
        int $sinceSeq,
        SearchRequest $request,
        TokenInterface $token,
        int $messageId,
    ): Generator {
        yield from $this->batcher->batch(
            $this->projectSince(
                $sinceSeq,
                $request,
                $token,
            ),
            $messageId,
        );
    }

    /**
     * The entry is read where it went, since that is the only place it still exists to judge visibility from.
     */
    private function fetchAndProjectMovedOut(
        PendingChange $change,
        TokenInterface $token,
    ): ?SyncResult {
        $entry = $this->backend->get($change->dn);
        if ($entry === null) {
            return null;
        }

        return $this->projector->projectMovedOut(
            $entry,
            $change,
            $token,
        );
    }

    private function fetchAndProject(
        PendingChange $change,
        SearchRequest $request,
        TokenInterface $token,
    ): ?SyncResult {
        $entry = $this->backend->get($change->dn);

        if ($entry === null) {
            return null;
        }

        return $this->projector->projectFetched(
            $entry,
            $change,
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
    ): Generator {
        yield new LdapMessageResponse(
            $messageId,
            new SearchResultDone(ResultCode::CANCELED),
            new SyncDoneControl(
                (new SyncCookie($origin, $lastSeq, $contentKey))->encode(),
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
