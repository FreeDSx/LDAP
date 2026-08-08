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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Operation\Response\SyncInfoMessage;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Protocol\Queue\Response\QueueWriterConfig;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeStream;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\Sync\Provider\Exception\MalformedSyncCookieException;
use FreeDSx\Ldap\Sync\Provider\SyncCookie;
use FreeDSx\Ldap\Sync\Provider\SyncPersistStreamer;
use FreeDSx\Ldap\Sync\Provider\SyncResult;
use FreeDSx\Ldap\Sync\Provider\SyncResultProjector;
use Generator;

/**
 * Serves RFC 4533 content-synchronization (refreshOnly and refreshAndPersist) from the change journal.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ServerSyncHandler implements ServerProtocolHandlerInterface
{
    use ServerSearchTrait;

    public function __construct(
        private readonly LdapBackendInterface $backend,
        private readonly SyncResultProjector $projector,
        private readonly SearchLimits $limits = new SearchLimits(),
        private readonly ?ChangeStream $changeStream = null,
        private readonly ?SyncPersistStreamer $persistStreamer = null,
        private readonly bool $persistSupported = false,
    ) {}

    /**
     * @throws OperationException
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $request = $this->getSearchRequestFromMessage($message);
        $control = $this->syncRequestControl($message);
        $stream = $this->changeStream;
        $streamer = $this->persistStreamer;

        if ($stream === null || $streamer === null) {
            throw new OperationException(
                'Content synchronization is not supported.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        $mode = $control->getMode();
        $this->assertModeSupported($mode);

        $baseDn = $this->assertBaseDnProvided($request);
        $messageId = $message->getMessageId();
        $latestSeq = $stream->latestSeq();
        $sinceSeq = $this->resolveSince($control, $stream, $latestSeq);
        $state = new SearchResultState();

        $entries = $sinceSeq === null
            ? $this->fullRefreshEntries($message, $request, $token, $state)
            : $this->incrementalEntries($message, $request, $token, $streamer, $sinceSeq, $state);

        $cookie = (new SyncCookie($stream->origin(), $latestSeq))->encode();
        $outcome = fn(): SearchOperationResult => SearchOperationResult::success(
            $message,
            $state->entriesReturned,
        );

        if ($mode === SyncRequestControl::MODE_REFRESH_AND_PERSIST) {
            $cancellation = new Cancellation();
            $boundary = $sinceSeq === null
                ? new SyncRefreshPresent(true, $cookie)
                : new SyncRefreshDelete(true, $cookie);

            return ResponseStream::streaming(
                $this->concat(
                    $this->withRefreshDone(
                        $entries,
                        $messageId,
                        $boundary,
                    ),
                    $streamer->stream(
                        $latestSeq,
                        $request,
                        $token,
                        $messageId,
                        $baseDn,
                        $cancellation,
                    ),
                ),
                $outcome,
                // Each change and keepalive flushes immediately for liveness; poll cancel after each.
                new QueueWriterConfig(flushPerMessage: true, signalInterval: 1),
                $cancellation,
            );
        }

        // refreshDeletes: a delete phase (true) only for an incremental sync that sent explicit
        // deletes; a full refresh is a present phase (false) the consumer reconciles by absence.
        return ResponseStream::streaming(
            $this->withSyncDone(
                $entries,
                $messageId,
                $baseDn,
                new SyncDoneControl($cookie, $sinceSeq !== null),
            ),
            $outcome,
        );
    }

    /**
     * @param Generator<LdapMessageResponse> ...$streams
     * @return Generator<LdapMessageResponse>
     */
    private function concat(Generator ...$streams): Generator
    {
        foreach ($streams as $stream) {
            yield from $stream;
        }
    }

    /**
     * @throws OperationException
     */
    private function assertModeSupported(int $mode): void
    {
        if ($mode !== SyncRequestControl::MODE_REFRESH_ONLY && $mode !== SyncRequestControl::MODE_REFRESH_AND_PERSIST) {
            throw new OperationException(
                'The requested content synchronization mode is not supported.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        if ($mode === SyncRequestControl::MODE_REFRESH_AND_PERSIST && !$this->persistSupported) {
            throw new OperationException(
                'The refreshAndPersist synchronization mode is not supported by this server.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }
    }

    /**
     * @param Generator<LdapMessageResponse> $entries
     * @return Generator<LdapMessageResponse>
     */
    private function withSyncDone(
        Generator $entries,
        int $messageId,
        Dn $baseDn,
        SyncDoneControl $doneControl,
    ): Generator {
        yield from $entries;

        yield new LdapMessageResponse(
            $messageId,
            new SearchResultDone(
                ResultCode::SUCCESS,
                $baseDn->toString(),
            ),
            $doneControl,
        );
    }

    /**
     * refreshAndPersist ends its refresh phase with a SyncInfo boundary instead of a SearchResultDone.
     *
     * @param Generator<LdapMessageResponse> $entries
     * @return Generator<LdapMessageResponse>
     */
    private function withRefreshDone(
        Generator $entries,
        int $messageId,
        SyncInfoMessage $boundary,
    ): Generator {
        yield from $entries;

        yield new LdapMessageResponse(
            $messageId,
            $boundary,
        );
    }

    /**
     * Empty/unknown cookie: every in-scope live entry as an add.
     *
     * @return Generator<LdapMessageResponse>
     */
    private function fullRefreshEntries(
        LdapMessageRequest $message,
        SearchRequest $request,
        TokenInterface $token,
        SearchResultState $state,
    ): Generator {
        $result = $this->backend->search(
            $request,
            SubentryVisibility::All, // we need all entries in a sync
            $this->controlsForBackend($message),
            $this->limits,
        );

        foreach ($result->entries as $entry) {
            yield from $this->emit(
                $this->toResponse(
                    $message->getMessageId(),
                    $this->projector->projectSearched($entry, $token),
                ),
                $state,
            );
        }
    }

    /**
     * Valid cookie: the net effect per entry since its seq, as adds and deletes.
     *
     * @return Generator<LdapMessageResponse>
     */
    private function incrementalEntries(
        LdapMessageRequest $message,
        SearchRequest $request,
        TokenInterface $token,
        SyncPersistStreamer $streamer,
        int $sinceSeq,
        SearchResultState $state,
    ): Generator {
        foreach ($streamer->projectSince($sinceSeq, $request, $token) as $result) {
            yield from $this->emit(
                $this->toResponse($message->getMessageId(), $result),
                $state,
            );
        }
    }

    private function toResponse(
        int $messageId,
        ?SyncResult $result,
    ): ?LdapMessageResponse {
        if ($result === null) {
            return null;
        }

        return new LdapMessageResponse(
            $messageId,
            $result->entry,
            $result->control,
        );
    }

    /**
     * @return Generator<LdapMessageResponse>
     */
    private function emit(
        ?LdapMessageResponse $response,
        SearchResultState $state,
    ): Generator {
        if ($response === null) {
            return;
        }

        $state->entriesReturned++;

        yield $response;
    }

    private function resolveSince(
        SyncRequestControl $control,
        ChangeStream $stream,
        int $latestSeq,
    ): ?int {
        $cookie = $control->getCookie();

        if ($cookie === null || $cookie === '' || $control->getReloadHint()) {
            return null;
        }

        try {
            $decoded = SyncCookie::decode($cookie);
        } catch (MalformedSyncCookieException) {
            return null;
        }

        if (!$decoded->origin->equals($stream->origin()) || $decoded->seq > $latestSeq) {
            return null;
        }

        // Cookie lapsed past the trim horizon: an incremental sync would miss pruned changes, so
        // serve a present-phase full refresh the consumer reconciles by absence.
        if (!$stream->retainsSince($decoded->seq)) {
            return null;
        }

        return $decoded->seq;
    }

    /**
     * @throws OperationException
     */
    private function syncRequestControl(LdapMessageRequest $message): SyncRequestControl
    {
        $control = $message->controls()->get(Control::OID_SYNC_REQUEST);

        if (!$control instanceof SyncRequestControl) {
            throw new OperationException(
                'The sync request control was expected, but not received.',
                ResultCode::PROTOCOL_ERROR,
            );
        }

        return $control;
    }
}
