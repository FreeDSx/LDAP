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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RequestRefusedException;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\Decoder\DecodeContext;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\LdapQueue;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseInterceptor;
use FreeDSx\Ldap\Server\Metrics\MetricsRecorderInterface;
use FreeDSx\Ldap\Server\Metrics\Observation\TrafficObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\NullMetricsRecorder;
use FreeDSx\Socket\Exception\ConnectionException;
use FreeDSx\Socket\Exception\PartialMessageException;
use FreeDSx\Socket\Exception\ReadTimeoutException;
use FreeDSx\Socket\Queue\Message;
use FreeDSx\Socket\Socket;
use Generator;

use function strlen;

/**
 * The LDAP Queue class for sending and receiving messages for servers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerQueue extends LdapQueue implements ConnectionControl
{
    /**
     * The bytes of the message decoded last.
     */
    private int $lastMessageBytes = 0;

    /**
     * The ASN.1 elements of the message decoded last, its nested parts included.
     */
    private int $lastMessageElements = 0;

    /**
     * The protocol operation tag of the message decoded last.
     */
    private int $lastOperationTag = 0;

    /**
     * @var ResponseInterceptor[]
     */
    private readonly array $interceptors;

    private bool $isSending = false;

    private bool $isCloseDeferred = false;

    /**
     * Whether the current read is ahead of the dispatcher and must not wait for room.
     */
    private bool $isReadingAhead = false;

    /**
     * @var LdapMessageResponse[]
     */
    private array $deferredMessages = [];

    /**
     * The failed write that every later write rethrows.
     */
    private ?ConnectionException $writeFailure = null;

    /**
     * @param ResponseInterceptor[] $interceptors applied to every outgoing response, in order.
     */
    public function __construct(
        Socket $socket,
        private readonly RequestMessageDecoder $messageDecoder,
        private readonly RequestArrival $arrival,
        private readonly LdapEncoder $ldapEncoder = new LdapEncoder(),
        array $interceptors = [],
        private readonly MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
        private readonly ReadAheadBuffer $readAhead = new ReadAheadBuffer(),
    ) {
        parent::__construct(
            $socket,
            $this->ldapEncoder,
        );
        $this->interceptors = $interceptors;
    }

    /**
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     */
    public function getMessage(?int $id = null): LdapMessageRequest
    {
        $pending = $id === null
            ? $this->readAhead->take()
            : null;

        return $pending ?? $this->readRequest($id);
    }

    /**
     * Returns a message to the front of the queue, so the next read hands it to the dispatcher as usual.
     */
    public function requeue(LdapMessageRequest $message): void
    {
        $this->readAhead->prepend($message);
    }

    /**
     * Holds a message read while peeking for the dispatcher, behind the ones that arrived before it.
     */
    public function buffer(LdapMessageRequest $message): void
    {
        $this->readAhead->append($message);
    }

    /**
     * Checks whether an Abandon or Cancel targeting a message ID has arrived.
     *
     * Other messages received while peeking are buffered.
     *
     * @throws RequestValidationException If a peeked message carries an unusable message ID.
     * @throws MessageDecodeException If a peeked message has an envelope that parses and a body that does not.
     */
    public function peekForCancelSignal(int $inFlightMessageId): ?LdapMessageRequest
    {
        // Nothing drains the buffer until the stream ends, so reading pauses here, and the socket holds the backlog.
        if ($this->isReadAheadPaused()) {
            return null;
        }

        if (!$this->hasPendingData()) {
            return null;
        }

        // Reads past anything already buffered; draining that here would re-inspect the same message forever.
        $message = $this->readAheadRequest();
        if ($message === null) {
            return null;
        }
        $request = $message->getRequest();

        if ($this->isAbandonOrCancelRequest($request, $inFlightMessageId)) {
            return $message;
        }
        $this->readAhead->append(
            $message,
            $this->lastMessageBytes,
        );

        // Buffered as well as signalled.
        // The session still has to end the way an unbind normally ends it.
        if ($request instanceof UnbindRequest) {
            return $message;
        }

        return null;
    }

    /**
     * Takes the next waiting message, buffered ones first, or null when none has arrived.
     *
     * @throws RequestValidationException If the message carries an unusable message ID.
     * @throws MessageDecodeException If the message has an envelope that parses and a body that does not.
     * @throws ConnectionException If the connection ends before the message has arrived.
     */
    public function pollMessage(): ?LdapMessageRequest
    {
        $pending = $this->readAhead->take();
        if ($pending !== null) {
            return $pending;
        }

        if (!$this->hasPendingData()) {
            return null;
        }

        return $this->readAheadRequest();
    }

    /**
     * Anything sent while a response is already going out waits for it to finish.
     *
     * @throws EncoderException
     * @throws ConnectionException
     */
    public function sendMessage(LdapMessageResponse ...$response): self
    {
        if ($this->isSending) {
            array_push(
                $this->deferredMessages,
                ...$response,
            );

            return $this;
        }
        $this->isSending = true;

        try {
            $this->sendLdapMessage(array_map(
                $this->applyInterceptors(...),
                $response,
            ));
        } finally {
            $this->isSending = false;
        }
        $this->flushDeferred();

        return $this;
    }

    /**
     * Releases what a request the upgrade discards reserved while arriving.
     */
    public function encrypt(): static
    {
        $this->arrival->arrived();
        parent::encrypt();

        return $this;
    }

    /**
     * A close that would truncate a response still going out waits until it has been written.
     */
    public function close(): void
    {
        if ($this->isSending) {
            $this->isCloseDeferred = true;

            return;
        }

        parent::close();
        $this->arrival->close();
    }

    /**
     * Stream an iterable message response set out the socket.
     *
     * @param iterable<LdapMessageResponse> $responses
     * @throws EncoderException
     * @throws ConnectionException when another write already holds the connection.
     */
    public function sendMessages(iterable $responses): self
    {
        // Only a concurrent writer can hold the connection here, and interleaving with it corrupts both.
        if ($this->isSending) {
            throw new ConnectionException('Another write already holds the connection.');
        }
        $this->isSending = true;

        try {
            $this->sendLdapMessage($this->interceptLazily($responses));
        } finally {
            $this->isSending = false;
        }

        $this->flushDeferred();

        return $this;
    }

    /**
     * Whether a write has failed on the connection.
     */
    public function hasFailedWrite(): bool
    {
        return $this->writeFailure !== null;
    }

    /**
     * Rethrows the failure of an earlier write, if one failed.
     *
     * @throws ConnectionException
     */
    public function throwIfWriteFailed(): void
    {
        if ($this->writeFailure !== null) {
            throw $this->writeFailure;
        }
    }

    /**
     * A write after a failed one fails at once instead of waiting on the same socket again.
     *
     * @throws ConnectionException
     */
    protected function writeToSocket(string $bytes): void
    {
        $this->throwIfWriteFailed();

        try {
            parent::writeToSocket($bytes);
        } catch (ConnectionException $e) {
            $this->writeFailure = $e;

            throw $e;
        }
    }

    /**
     * Count the LDAP bytes sent for each outgoing response.
     */
    protected function onMessageEncoded(string $encoded): void
    {
        $this->metricsRecorder->trafficObserved(new TrafficObservation(
            bytesSent: strlen($encoded),
        ));
    }

    /**
     * A request that has begun to arrive must finish within the read timeout, including any wait to be admitted.
     *
     * @throws ConnectionException
     * @throws PartialMessageException when a request read ahead has no room yet to arrive.
     */
    protected function addToAvailableBufferOrFail(): void
    {
        $isRequestArriving = $this->hasBuffer();
        $this->admitArriving();
        $this->readWithin($this->arrival->readTimeout($isRequestArriving));
    }

    /**
     * Count the LDAP bytes received for each decoded request.
     */
    protected function onMessageDecoded(Message $message): void
    {
        $this->arrival->arrived();
        $this->lastMessageBytes = (int) $message->getLastPosition();
        $this->metricsRecorder->trafficObserved(new TrafficObservation(
            bytesReceived: $this->lastMessageBytes,
        ));
    }

    /**
     * Holds the request to the size the session's bind allows, and records the size a partial one declared.
     *
     * @throws RequestSizeExceededException
     * @throws ProtocolException
     * @throws PartialMessageException
     */
    protected function decode(string $bytes): Message
    {
        $this->arrival->limitDecoding($this->ldapEncoder);

        try {
            return parent::decode($bytes);
        } catch (PartialMessageException $partial) {
            $this->arrival->arriving($this->pduLengthOf($partial));

            throw $partial;
        }
    }

    /**
     * {@inheritDoc}
     * @throws ProtocolException
     * @throws MessageDecodeException
     */
    protected function constructMessage(Message $message, ?int $id = null): LdapMessageRequest
    {
        $type = $message->getMessage();

        if (!$type instanceof AbstractType) {
            throw new ProtocolException('The message received is invalid.');
        }

        // The encoder still holds the count from decoding this message, which always runs right before it is built.
        $elements = $this->ldapEncoder->getLastElementCount();
        $nestedParts = new DecodeContext($this->arrival->elementsLeftAfter($elements));
        $request = $this->messageDecoder->decode(
            $type,
            $nestedParts,
        );
        $this->lastMessageElements = $elements + $nestedParts->elementsDecoded();
        $this->lastOperationTag = (int) $type->getChild(1)?->getTagNumber();

        return $request;
    }

    /**
     * Apply each interceptor to a response one message at a time, preserving lazy streaming.
     *
     * @param iterable<LdapMessageResponse> $responses
     * @return Generator<LdapMessageResponse>
     */
    private function interceptLazily(iterable $responses): Generator
    {
        foreach ($responses as $response) {
            if ($this->isCloseDeferred) {
                return;
            }

            yield $this->applyInterceptors($response);
        }
    }

    /**
     * Sends what was held back, then applies a close that waited with it.
     *
     * @throws EncoderException
     */
    private function flushDeferred(): void
    {
        $deferred = $this->deferredMessages;
        $this->deferredMessages = [];

        if ($deferred !== []) {
            $this->sendMessage(...$deferred);
        }
        if (!$this->isCloseDeferred) {
            return;
        }

        $this->isCloseDeferred = false;
        $this->close();
    }

    /**
     * Reads within the time left for a request to arrive, or as long as the idle timeout allows when it is null.
     *
     * @throws ConnectionException
     */
    private function readWithin(?float $timeout): void
    {
        if ($timeout === null) {
            parent::addToAvailableBufferOrFail();

            return;
        }

        try {
            $bytes = $this->socket->read(
                true,
                $timeout,
            );
        } catch (ReadTimeoutException $e) {
            $this->arrival->timedOut($e);
        }
        if ($bytes === false) {
            throw new ConnectionException('The connection to the server has been lost.');
        }

        $this->buffer .= $bytes;
    }

    /**
     * Reading ahead never waits for room the request in progress on this connection may be holding.
     *
     * @throws PartialMessageException when a request read ahead has no room yet, leaving it buffered for a later read.
     * @throws ConnectionException
     */
    private function admitArriving(): void
    {
        if ($this->isReadingAhead) {
            $this->arrival->admitAtOnce();

            return;
        }

        $this->arrival->admit();
    }

    /**
     * Read-ahead pauses once its buffer is full or the process holds all it may.
     */
    private function isReadAheadPaused(): bool
    {
        return $this->readAhead->isFull()
            || !$this->arrival->hasRoomToReadAhead();
    }

    /**
     * The bytes the partial request declared, known to the ASN.1 decoder once its length has arrived.
     */
    private function pduLengthOf(PartialMessageException $partial): ?int
    {
        $cause = $partial->getPrevious();

        return $cause instanceof PartialPduException
            ? $cause->getPduLength()
            : null;
    }

    private function applyInterceptors(LdapMessageResponse $response): LdapMessageResponse
    {
        foreach ($this->interceptors as $interceptor) {
            $response = $interceptor->intercept($response);
        }

        return $response;
    }

    /**
     * Holding a request only once its decoding is done keeps the request and its ASN.1 out of a refusal's trace.
     *
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     * @throws RequestRefusedException when the process has no room to hold the request.
     * @throws PartialMessageException when a request read ahead has no room yet to arrive.
     */
    private function readRequest(?int $id): LdapMessageRequest
    {
        $message = $this->getAndValidateMessage($id);
        if (!$message instanceof LdapMessageRequest) {
            throw new ProtocolException(sprintf(
                'Expected an instance of LdapMessageResponse but got: %s',
                get_class($message),
            ));
        }
        $isHeld = $this->arrival->hold(
            $message,
            $this->lastMessageBytes,
            $this->lastMessageElements,
        );
        if (!$isHeld) {
            $this->arrival->refuse(
                $message->getMessageId(),
                $this->lastOperationTag,
                $this->lastMessageBytes,
                $this->lastMessageElements,
            );
        }

        return $message;
    }

    /**
     * @param RequestInterface $request
     * @param int $inFlightMessageId
     * @return bool
     */
    private function isAbandonOrCancelRequest(
        RequestInterface $request,
        int $inFlightMessageId,
    ): bool {
        return ($request instanceof AbandonRequest || $request instanceof CancelRequest)
            && $request->getMessageId() === $inFlightMessageId;
    }

    /**
     * Reads a request ahead of the dispatcher, or returns null when there is no room for it yet.
     *
     * @throws RequestValidationException when the request uses the message ID the validation middleware would refuse.
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     */
    private function readAheadRequest(): ?LdapMessageRequest
    {
        $this->isReadingAhead = true;
        try {
            $message = $this->readRequest(null);
        } catch (PartialMessageException) {
            return null;
        } finally {
            $this->isReadingAhead = false;
        }
        if ($message->getMessageId() === 0) {
            throw new RequestValidationException('The message ID 0 cannot be used in a client request.');
        }

        return $message;
    }
}
