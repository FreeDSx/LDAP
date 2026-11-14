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

namespace FreeDSx\Ldap\Protocol\Queue\Budget;

use FreeDSx\Ldap\Exception\RequestRefusedException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Socket\Exception\ConnectionException;
use WeakMap;

use function ceil;
use function intdiv;
use function min;

/**
 * The requests one connection is receiving and decoded, held against its process budget and its identity's share.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class HeldRequests
{
    /**
     * Requests estimated to hold no more than this are counted but never wait for room or get refused.
     */
    private const ALWAYS_HELD_BYTES = 4_096;

    /**
     * The fewest elements a request holds: its message ID and its operation.
     */
    private const MIN_ELEMENTS = 2;

    /**
     * What a decoded request holds for each of its bytes, measured across requests of every shape.
     */
    private const DECODED_BYTES_PER_BYTE = 1.15;

    /**
     * What a decoded request holds for each of its elements on top of its bytes, covering the costliest shape measured.
     */
    private const DECODED_BYTES_PER_ELEMENT = 160;

    /**
     * What the request arriving now will hold for its declared bytes, reserved from its admission until it has arrived.
     */
    private ?BudgetReservation $arriving = null;

    /**
     * Whether the connection has closed, after which nothing more is admitted.
     */
    private bool $isClosed = false;

    /**
     * Intentionally never read (thus the phpstan ignore, which normally should *not* be done), as it only keeps each
     * decoded request's reservation for as long as the request is alive.
     *
     * @var WeakMap<LdapMessageRequest, BudgetReservation>
     * @phpstan-ignore shipmonk.deadProperty.neverRead
     */
    private WeakMap $decoded;

    /**
     * @param int $limit the bytes the process may hold, or 0 for no limit.
     */
    public function __construct(
        private readonly RequestBudget $budget,
        private readonly int $limit,
        private readonly IdentityShare $share,
    ) {
        $this->decoded = new WeakMap();
    }

    /**
     * The bytes a request decoded from the bytes and elements holds.
     */
    public static function estimate(
        int $bytes,
        int $elements,
    ): int {
        return (int) ceil($bytes * self::DECODED_BYTES_PER_BYTE) + $elements * self::DECODED_BYTES_PER_ELEMENT;
    }

    /**
     * What the largest request allowed holds once decoded, without bound when requests have no size limit.
     */
    public static function largestHeld(
        int $maxRequestSize,
        int $maxRequestElements,
    ): int {
        if ($maxRequestSize === 0) {
            return PHP_INT_MAX;
        }

        return self::estimate(
            $maxRequestSize,
            self::mostElements(
                $maxRequestSize,
                $maxRequestElements,
            ),
        );
    }

    /**
     * Whether a request declaring the bytes could ever be admitted.
     */
    public function couldEverAdmit(int $pduLength): bool
    {
        if ($this->limit === 0) {
            return true;
        }
        $cost = self::admissionCost($pduLength);

        return $cost <= self::ALWAYS_HELD_BYTES
            || $cost <= $this->share->current()->limit;
    }

    /**
     * Reserves for the declared bytes before the rest is read, or returns false once the deadline in microtime passes.
     *
     * @throws ConnectionException when the connection closes while it waits for room.
     */
    public function admit(
        int $pduLength,
        ?float $deadline,
    ): bool {
        return $this->tryAdmit($pduLength)
            || $this->budget->waitForRoom(
                fn(): bool => $this->tryAdmit($pduLength),
                $deadline,
            );
    }

    /**
     * Reserves for the declared bytes when the process and the share have room now, or returns false without waiting.
     *
     * @throws ConnectionException when the connection has closed.
     */
    public function tryAdmit(int $pduLength): bool
    {
        if ($this->isClosed) {
            throw new ConnectionException('The connection closed before its request had room to arrive.');
        }
        if ($this->limit === 0 || $this->arriving !== null) {
            return true;
        }
        $share = $this->share->current();
        $cost = self::admissionCost($pduLength);
        if ($cost > self::ALWAYS_HELD_BYTES && !$this->budget->fits($cost, $this->limit, $share)) {
            return false;
        }
        $this->arriving = $this->budget->reserveAnyway(
            $cost,
            $share,
        );

        return true;
    }

    /**
     * Releases what the request that arrived, or was discarded, reserved while arriving.
     */
    public function arrived(): void
    {
        $this->arriving = null;
    }

    /**
     * Releases what the request arriving now reserved and admits nothing more, once the connection has closed.
     */
    public function close(): void
    {
        $this->isClosed = true;
        $this->arriving = null;
    }

    /**
     * Whether the process and the share hold less than they may and requests may still be read ahead.
     */
    public function hasRoomToReadAhead(): bool
    {
        if ($this->limit === 0) {
            return true;
        }
        $share = $this->share->current();

        return $this->budget->held() < $this->limit
            && $this->budget->heldBy($share) < $share->limit;
    }

    /**
     * Counts a decoded request at what it holds for as long as it is alive, or returns false when there is no room.
     */
    public function hold(
        LdapMessageRequest $request,
        int $bytes,
        int $elements,
    ): bool {
        if ($this->limit === 0) {
            return true;
        }

        $share = $this->share->current();
        $estimate = self::estimate(
            $bytes,
            $elements,
        );
        $reservation = $estimate <= self::ALWAYS_HELD_BYTES
            ? $this->budget->reserveAnyway(
                $estimate,
                $share,
            )
            : $this->budget->reserve(
                $estimate,
                $this->limit,
                $share,
            );
        if ($reservation === null) {
            return false;
        }
        $this->decoded[$request] = $reservation;

        return true;
    }

    /**
     * Refuses a request there was no room to hold, as one that could never fit when it is larger than the share.
     *
     * @throws RequestRefusedException
     */
    public function refuse(
        int $messageId,
        int $operationTag,
        int $bytes,
        int $elements,
    ): never {
        $share = $this->share->current();
        $estimate = self::estimate(
            $bytes,
            $elements,
        );

        // The share is never less than the largest request allowed, unless the whole limit is.
        if ($estimate > $share->limit) {
            throw new RequestRefusedException(
                $messageId,
                $operationTag,
                'The request is larger than the server can hold.',
                resultCode: ResultCode::ADMIN_LIMIT_EXCEEDED,
            );
        }
        if ($this->budget->heldBy($share) + $estimate > $share->limit) {
            throw new RequestRefusedException(
                $messageId,
                $operationTag,
                'The server holds as much as it allows one identity to.',
                resultCode: ResultCode::BUSY,
            );
        }

        throw new RequestRefusedException(
            $messageId,
            $operationTag,
            'The server is too busy to hold the request.',
            resultCode: ResultCode::BUSY,
        );
    }

    /**
     * What a request declaring the bytes will hold once decoded, counting only the elements every request has.
     */
    private static function admissionCost(int $pduLength): int
    {
        return self::estimate(
            $pduLength,
            self::MIN_ELEMENTS,
        );
    }

    /**
     * The most elements the largest request allowed can carry, at most one for every two of its bytes.
     */
    private static function mostElements(
        int $maxRequestSize,
        int $maxRequestElements,
    ): int {
        $mostBySize = intdiv(
            $maxRequestSize,
            2,
        );

        return $maxRequestElements === 0
            ? $mostBySize
            : min(
                $maxRequestElements,
                $mostBySize,
            );
    }
}
