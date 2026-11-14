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

namespace FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use Throwable;

use function random_bytes;

/**
 * Finds, keeps and ends the paged searches a connection has left unfinished.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PagingSessionTracker
{
    /**
     * @param int $maxSessions the unfinished paged searches a connection may keep, or 0 for no limit.
     */
    public function __construct(
        private PagingSessions $sessions,
        private int $maxSessions = 0,
        private ?EventLogger $eventLogger = null,
        private PagingRequestFingerprint $fingerprint = new PagingRequestFingerprint(),
    ) {}

    /**
     * The session a continuation resumes, or null for a search that is just starting.
     *
     * @throws OperationException
     */
    public function find(PagingRequest $pagingRequest): ?PagingSession
    {
        if ($pagingRequest->isPagingStart()) {
            return null;
        }

        try {
            return $this->sessions->findByNextCookie($pagingRequest->getCookie());
        } catch (ProtocolException $e) {
            // An aged-out session leaves no record, so a resumed one and an invented one answer alike.
            throw new OperationException(
                $e->getMessage(),
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }
    }

    /**
     * @throws OperationException when the continuation is not the search the session started.
     */
    public function assertSameSearch(
        PagingRequest $pagingRequest,
        PagingSession $session,
    ): void {
        if ($this->fingerprint->of($pagingRequest) === $session->fingerprint()) {
            return;
        }

        throw new OperationException(
            'The search request and controls must be identical between paging requests.',
            ResultCode::OPERATIONS_ERROR,
        );
    }

    /**
     * Keeps the search resumable from the cursor under a new cookie, starting a session after its first page.
     *
     * @throws OperationException
     * @throws ProtocolException
     */
    public function keep(
        PagingRequest $pagingRequest,
        ?PagingSession $session,
        PageCursor $cursor,
    ): string {
        $cookie = self::generateCookie();

        if ($session !== null) {
            $session->advance(
                $cookie,
                $cursor,
            );

            return $cookie;
        }

        $this->evictOldestAtLimit();
        $this->sessions->add(new PagingSession(
            $this->fingerprint->of($pagingRequest),
            $cookie,
            $cursor,
        ));

        return $cookie;
    }

    public function end(PagingSession $session): void
    {
        $this->sessions->remove($session);
    }

    /**
     * Unfinished sessions would otherwise accumulate for the life of the connection.
     */
    private function evictOldestAtLimit(): void
    {
        if (!$this->sessions->evictOldestAtLimit($this->maxSessions)) {
            return;
        }

        $this->eventLogger?->record(
            ServerEvent::PagingSessionEvicted,
            [EventContext::LIMIT => $this->maxSessions],
        );
    }

    /**
     * @throws OperationException
     */
    private static function generateCookie(): string
    {
        try {
            return random_bytes(16);
        } catch (Throwable) {
            throw new OperationException(
                'Internal server error.',
                ResultCode::OPERATIONS_ERROR,
            );
        }
    }
}
