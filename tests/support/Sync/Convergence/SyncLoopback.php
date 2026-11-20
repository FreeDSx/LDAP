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

use Closure;
use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncNewCookie;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshDelete;
use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncRefreshPresent;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Decoder\ResponseMessageDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Sync\Consumer\ReplicaConsumer;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\Session;
use Generator;
use RuntimeException;

/**
 * Hands a provider's sync messages to one consumer through the wire encoding, as a client connection delivers them.
 */
final class SyncLoopback
{
    private readonly ResponseMessageDecoder $decoder;

    private readonly LdapEncoder $encoder;

    /**
     * @var Generator<LdapMessageResponse>|null
     */
    private ?Generator $stream = null;

    /**
     * Whether the current message was handled, in which case reading the next one first resumes the provider.
     */
    private bool $handled = false;

    private Session $session;

    private bool $startedWithoutCookie = false;

    /**
     * @var list<string>
     */
    private array $leaks = [];

    /**
     * @param Closure(?string): Generator<LdapMessageResponse> $open Starts a sync from the cookie.
     */
    public function __construct(
        private readonly Closure $open,
        private readonly ReplicaConsumer $consumer,
    ) {
        $this->decoder = Container::forClient(new ClientOptions())->get(ResponseMessageDecoder::class);
        $this->encoder = new LdapEncoder();
        $this->session = new Session(
            Session::MODE_LISTEN,
            null,
        );
    }

    /**
     * Handles messages until the provider ends its next poll, or until the limit when a crash cuts the sync short.
     *
     * @return bool whether a poll ended before the limit
     */
    public function drain(?int $limit = null): bool
    {
        $handled = 0;

        while ($limit === null || $handled < $limit) {
            ++$handled;

            if ($this->handle($this->next())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the sync started without a cookie, which makes it a full refresh.
     */
    public function startedWithoutCookie(): bool
    {
        return $this->startedWithoutCookie;
    }

    /**
     * The DNs from the hidden subtree any message named.
     *
     * @return list<string>
     */
    public function leaks(): array
    {
        return $this->leaks;
    }

    private function next(): LdapMessageResponse
    {
        if ($this->stream === null) {
            $this->connect();
        } elseif ($this->handled) {
            $this->stream->next();
        }
        $stream = $this->stream ?? throw new RuntimeException('The sync has no stream.');
        $this->handled = true;

        if (!$stream->valid()) {
            throw new RuntimeException('The provider ended the sync without a result.');
        }

        return $this->received($stream->current());
    }

    /**
     * Starts a sync as the replica daemon does, from the cookie its checkpoint holds.
     */
    private function connect(): void
    {
        $cookie = $this->consumer->startingCookie();

        $this->startedWithoutCookie = $cookie === null;
        $this->session = new Session(
            Session::MODE_LISTEN,
            $cookie,
        );
        $this->consumer->startRefresh($cookie);
        $this->open($cookie);
    }

    private function open(?string $cookie): void
    {
        $this->stream = ($this->open)($cookie);
        $this->handled = false;
    }

    /**
     * @return bool whether the message ended a poll
     */
    private function handle(LdapMessageResponse $message): bool
    {
        $response = $message->getResponse();

        return match (true) {
            $response instanceof SearchResultEntry => $this->applyEntry($message),
            $response instanceof SyncIdSet => $this->applyIdSet($message),
            $response instanceof SyncRefreshPresent,
            $response instanceof SyncRefreshDelete => $this->endPhase($response),
            $response instanceof SyncNewCookie => $this->endPoll($response),
            $response instanceof SearchResultDone => $this->refreshRequired($message),
            default => throw new RuntimeException('The provider sent a message a sync does not expect.'),
        };
    }

    private function applyEntry(LdapMessageResponse $message): bool
    {
        $result = new SyncEntryResult(new EntryResult($message));
        $dn = $result->getEntry()->getDn();

        if ($dn->toString() !== '' && DirectorySnapshot::isHidden($dn->normalize())) {
            $this->leaks[] = $dn->toString();
        }

        $this->consumer->applyEntry(
            $result,
            $this->session,
        );

        return false;
    }

    private function applyIdSet(LdapMessageResponse $message): bool
    {
        $result = new SyncIdSetResult($message);

        $this->updateCookie($result->getCookie());
        $this->consumer->applyIdSet(
            $result,
            $this->session,
        );

        return false;
    }

    private function endPhase(SyncRefreshPresent|SyncRefreshDelete $response): bool
    {
        $deletes = $response instanceof SyncRefreshDelete;
        $this->updateCookie($response->getCookie());

        if (!$response->getRefreshDone()) {
            $this->session->updatePhase($deletes ? Session::PHASE_DELETE : Session::PHASE_PRESENT);

            return false;
        }

        $this->session
            ->updatePhase(null)
            ->markRefreshComplete($deletes);
        $this->consumer->reconcileRefresh($this->session);

        return false;
    }

    private function endPoll(SyncNewCookie $response): bool
    {
        $this->updateCookie($response->getCookie());

        return true;
    }

    /**
     * Starts over from the cookie the provider gave, as a client does on e-syncRefreshRequired.
     */
    private function refreshRequired(LdapMessageResponse $message): bool
    {
        $response = $message->getResponse();
        $required = $response instanceof SearchResultDone
            && $response->getResultCode() === ResultCode::SYNCHRONIZATION_REFRESH_REQUIRED;

        if (!$required) {
            throw new RuntimeException('The provider ended the sync.');
        }
        $cookie = $message->controls()
            ->getByClass(SyncDoneControl::class)
            ?->getCookie();

        $this->session->resetRefreshState();
        $this->consumer->startRefresh($cookie);
        $this->open($cookie);

        return false;
    }

    private function updateCookie(?string $cookie): void
    {
        if ($cookie === null || $this->session->getCookie() === $cookie) {
            return;
        }

        $this->session->updateCookie($cookie);
        $this->consumer->persistCookie($cookie);
    }

    private function received(LdapMessageResponse $message): LdapMessageResponse
    {
        $received = $this->decoder->decode($this->encoder->decode($this->encoder->encode($message->toAsn1())));

        if (!$received instanceof LdapMessageResponse) {
            throw new RuntimeException('The provider sent something other than a response.');
        }

        return $received;
    }
}
