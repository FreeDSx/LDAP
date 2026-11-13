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

/**
 * The request one connection is receiving and the requests it decoded, held against the request budget of its process.
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
     * Whether a request declaring the bytes could ever be admitted.
     */
    public function couldEverAdmit(int $pduLength): bool
    {
        if ($this->limit === 0) {
            return true;
        }
        $cost = self::admissionCost($pduLength);

        return $cost <= self::ALWAYS_HELD_BYTES
            || $cost <= $this->limit;
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
     * Reserves for the declared bytes when the process has room for them now, or returns false without waiting.
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
        $cost = self::admissionCost($pduLength);
        if ($cost > self::ALWAYS_HELD_BYTES && !$this->budget->fits($cost, $this->limit)) {
            return false;
        }
        $this->arriving = $this->budget->reserveAnyway($cost);

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
     * Whether the process holds less than it may and requests may still be read ahead of the one in progress.
     */
    public function hasRoomToReadAhead(): bool
    {
        return $this->limit === 0
            || $this->budget->held() < $this->limit;
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

        $estimate = self::estimate(
            $bytes,
            $elements,
        );
        $reservation = $estimate <= self::ALWAYS_HELD_BYTES
            ? $this->budget->reserveAnyway($estimate)
            : $this->budget->reserve(
                $estimate,
                $this->limit,
            );
        if ($reservation === null) {
            return false;
        }
        $this->decoded[$request] = $reservation;

        return true;
    }

    /**
     * Refuses a request there was no room to hold, as one that could never fit when it is larger than the limit.
     *
     * @throws RequestRefusedException
     */
    public function refuse(
        int $messageId,
        int $operationTag,
        int $bytes,
        int $elements,
    ): never {
        $estimate = self::estimate(
            $bytes,
            $elements,
        );
        if ($estimate > $this->limit) {
            throw new RequestRefusedException(
                $messageId,
                $operationTag,
                'The request is larger than the server can hold.',
                resultCode: ResultCode::ADMIN_LIMIT_EXCEEDED,
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
}
