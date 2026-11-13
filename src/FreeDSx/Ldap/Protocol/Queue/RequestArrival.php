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

namespace FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Ldap\Exception\RequestRefusedException;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Budget\HeldRequests;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Exception\IdleTimeoutException;
use FreeDSx\Socket\Exception\PartialMessageException;
use FreeDSx\Socket\Exception\ReadTimeoutException;

use function microtime;
use function sprintf;

/**
 * The limits a request on one connection must arrive within: its size, its elements, its time and the room to hold it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class RequestArrival
{
    /**
     * The request size the encoder holds, or null until the first decode sets it.
     */
    private ?int $maxSize = null;

    /**
     * When the request partly received must have fully arrived, or null until a wait finds one.
     */
    private ?float $deadline = null;

    /**
     * The bytes the request arriving now declared, or null until its length has arrived.
     */
    private ?int $pduLength = null;

    public function __construct(
        private readonly RequestLimits $limits,
        private readonly HeldRequests $held,
    ) {}

    /**
     * Holds the encoder to the size the session's bind allows now.
     */
    public function limitDecoding(LdapEncoder $encoder): void
    {
        $maxSize = $this->limits->maxSize();
        if ($maxSize === $this->maxSize) {
            return;
        }
        $this->maxSize = $maxSize;
        $encoder->setOptions($this->limits->encoderOptions($maxSize));
    }

    /**
     * The elements a request's nested parts may still hold, or null when there is no limit.
     */
    public function elementsLeftAfter(int $elementCount): ?int
    {
        return $this->limits->elementsLeftAfter($elementCount);
    }

    /**
     * The seconds the next read may wait on a request that has begun to arrive, or null to leave it to the idle timeout.
     */
    public function readTimeout(bool $isRequestArriving): ?float
    {
        $deadline = $this->deadline($isRequestArriving);

        return $deadline === null
            ? null
            : $deadline - microtime(true);
    }

    /**
     * Records the bytes the request arriving now declared, once its length has arrived.
     *
     * @throws RequestSizeExceededException when the process could never hold a request that large.
     */
    public function arriving(?int $pduLength): void
    {
        if ($pduLength === null) {
            return;
        }
        if (!$this->held->couldEverAdmit($pduLength)) {
            throw new RequestSizeExceededException('The request is larger than the server can hold.');
        }

        $this->pduLength = $pduLength;
    }

    /**
     * Leaves the rest of the request arriving now on the socket until the process has room for all it declared.
     *
     * @throws ReadTimeoutException when the request runs out of time to arrive first.
     * @throws IdleTimeoutException when there is no read timeout and the idle timeout passes first.
     * @throws ConnectionException when the connection closes first.
     */
    public function admit(): void
    {
        if ($this->pduLength === null) {
            return;
        }
        $deadline = $this->deadline(true);
        if ($deadline === null) {
            $this->admitWhileIdle($this->pduLength);

            return;
        }

        $isAdmitted = $this->held->admit(
            $this->pduLength,
            $deadline,
        );
        if (!$isAdmitted) {
            $this->admissionTimedOut();
        }
    }

    /**
     * Admits the request arriving now only if there is room already, otherwise leaving no deadline running.
     *
     * @throws PartialMessageException when there is no room yet, leaving the rest of the request on the socket.
     * @throws ConnectionException when the connection has closed.
     */
    public function admitAtOnce(): void
    {
        if ($this->pduLength === null || $this->held->tryAdmit($this->pduLength)) {
            return;
        }
        // A pause the server chose does not count against the time the client has to send the request.
        $this->deadline = null;

        throw new PartialMessageException('There is no room yet to read the rest of the request.');
    }

    /**
     * Whether the process holds less than it may and requests may still be read ahead of the one in progress.
     */
    public function hasRoomToReadAhead(): bool
    {
        return $this->held->hasRoomToReadAhead();
    }

    /**
     * Counts a decoded request for as long as it is alive, or returns false when the process has no room to hold it.
     */
    public function hold(
        LdapMessageRequest $request,
        int $bytes,
        int $elements,
    ): bool {
        return $this->held->hold(
            $request,
            $bytes,
            $elements,
        );
    }

    /**
     * Refuses a request there was no room to hold.
     *
     * @throws RequestRefusedException
     */
    public function refuse(
        int $messageId,
        int $operationTag,
        int $bytes,
        int $elements,
    ): never {
        $this->held->refuse(
            $messageId,
            $operationTag,
            $bytes,
            $elements,
        );
    }

    /**
     * Reports the request as taking too long to arrive.
     *
     * @throws ReadTimeoutException
     */
    public function timedOut(ReadTimeoutException $timeout): never
    {
        throw new ReadTimeoutException(
            sprintf(
                'The request did not finish arriving within %d seconds.',
                $this->limits->readTimeout(),
            ),
            previous: $timeout,
        );
    }

    /**
     * Starts over for the next request, releasing what the last one reserved while it arrived or was discarded.
     */
    public function arrived(): void
    {
        $this->deadline = null;
        $this->pduLength = null;
        $this->held->arrived();
    }

    /**
     * Releases what the request arriving now reserved and ends any wait for room, once the connection has closed.
     */
    public function close(): void
    {
        $this->arrived();
        $this->held->close();
    }

    /**
     * Reports the request as finding no room to arrive within the read timeout.
     *
     * @throws ReadTimeoutException
     */
    private function admissionTimedOut(): never
    {
        throw new ReadTimeoutException(sprintf(
            'The server had no room to read the rest of the request within %d seconds.',
            $this->limits->readTimeout(),
        ));
    }

    /**
     * Without a request deadline the wait ends when the idle timeout would have ended a read.
     *
     * @throws IdleTimeoutException
     */
    private function admitWhileIdle(int $pduLength): void
    {
        $idleTimeout = $this->limits->idleTimeout();
        $isAdmitted = $this->held->admit(
            $pduLength,
            $idleTimeout > 0 ? microtime(true) + $idleTimeout : null,
        );
        if ($isAdmitted) {
            return;
        }

        throw new IdleTimeoutException(sprintf(
            'The connection waited for room to read for longer than the idle timeout of %d seconds.',
            $idleTimeout,
        ));
    }

    /**
     * When the request partly received must have arrived, or null when only the idle timeout applies.
     */
    private function deadline(bool $isRequestArriving): ?float
    {
        $timeout = $this->limits->readTimeout();
        // Between requests only the idle timeout applies.
        if ($timeout === 0 || !$isRequestArriving) {
            return null;
        }

        return $this->deadline ??= microtime(true) + $timeout;
    }
}
