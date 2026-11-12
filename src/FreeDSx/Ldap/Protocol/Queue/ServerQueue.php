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
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\MessageDecodeException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RequestSizeExceededException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
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
use FreeDSx\Socket\Queue\Message;
use FreeDSx\Socket\Socket;
use Generator;

use function count;
use function strlen;

/**
 * The LDAP Queue class for sending and receiving messages for servers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerQueue extends LdapQueue implements ConnectionControl
{
    /**
     * Well above what a pipelining client sends mid-stream, but low enough to bound what one connection can buffer.
     */
    private const MAX_PENDING_MESSAGES = 128;

    /**
     * Bounds what read-ahead holds by size, as a few large requests decode into far more memory than many small ones.
     */
    private const MAX_PENDING_BYTES = 65_536;

    /**
     * @var LdapMessageRequest[]
     */
    private array $pendingMessages = [];

    /**
     * The bytes of the messages read ahead into the buffer, counted until it next empties.
     */
    private int $pendingBytes = 0;

    /**
     * The bytes of the message decoded last.
     */
    private int $lastMessageBytes = 0;

    /**
     * @var ResponseInterceptor[]
     */
    private readonly array $interceptors;

    private bool $isSending = false;

    private bool $isCloseDeferred = false;

    /**
     * @var LdapMessageResponse[]
     */
    private array $deferredMessages = [];

    /**
     * The request size the encoder holds, or null until the first decode sets it.
     */
    private ?int $maxSize = null;

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
        private readonly RequestLimits $limits,
        private readonly LdapEncoder $ldapEncoder = new LdapEncoder(),
        array $interceptors = [],
        private readonly MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
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
            ? $this->takePending()
            : null;

        return $pending ?? $this->readRequest($id);
    }

    /**
     * Returns a message to the front of the queue, so the next read hands it to the dispatcher as usual.
     */
    public function requeue(LdapMessageRequest $message): void
    {
        array_unshift(
            $this->pendingMessages,
            $message,
        );
    }

    /**
     * Holds a message read while peeking for the dispatcher, behind the ones that arrived before it.
     */
    public function buffer(LdapMessageRequest $message): void
    {
        $this->pendingMessages[] = $message;
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
        if ($this->isReadAheadFull()) {
            return null;
        }

        if (!$this->hasPendingData()) {
            return null;
        }

        // Reads past anything already buffered; draining that here would re-inspect the same message forever.
        $message = $this->readAheadRequest();
        $request = $message->getRequest();

        if ($this->isAbandonOrCancelRequest($request, $inFlightMessageId)) {
            return $message;
        }
        $this->pendingMessages[] = $message;
        $this->pendingBytes += $this->lastMessageBytes;

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
     */
    public function pollMessage(): ?LdapMessageRequest
    {
        $pending = $this->takePending();
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
     * A close that would truncate a response still going out waits until it has been written.
     */
    public function close(): void
    {
        if ($this->isSending) {
            $this->isCloseDeferred = true;

            return;
        }

        parent::close();
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
     * Count the LDAP bytes received for each decoded request.
     */
    protected function onMessageDecoded(Message $message): void
    {
        $this->lastMessageBytes = (int) $message->getLastPosition();
        $this->metricsRecorder->trafficObserved(new TrafficObservation(
            bytesReceived: $this->lastMessageBytes,
        ));
    }

    /**
     * Holds the request to the size the session's bind allows when it is read.
     *
     * @throws RequestSizeExceededException
     * @throws ProtocolException
     */
    protected function decode(string $bytes): Message
    {
        $maxSize = $this->limits->maxSize();
        if ($maxSize !== $this->maxSize) {
            $this->maxSize = $maxSize;
            $this->ldapEncoder->setOptions($this->limits->encoderOptions($maxSize));
        }

        return parent::decode($bytes);
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
        return $this->messageDecoder->decode(
            $type,
            $this->limits->elementsLeftAfter($this->ldapEncoder->getLastElementCount()),
        );
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
     * Whether the buffer holds as many messages, or as many bytes of them, as read-ahead may.
     */
    private function isReadAheadFull(): bool
    {
        return count($this->pendingMessages) >= self::MAX_PENDING_MESSAGES
            || $this->pendingBytes >= self::MAX_PENDING_BYTES;
    }

    /**
     * Takes the oldest buffered message, or null when none is buffered.
     */
    private function takePending(): ?LdapMessageRequest
    {
        $message = array_shift($this->pendingMessages);
        // The bytes are counted for the buffer as a whole, so they are only forgotten once it empties.
        if ($this->pendingMessages === []) {
            $this->pendingBytes = 0;
        }

        return $message;
    }

    private function applyInterceptors(LdapMessageResponse $response): LdapMessageResponse
    {
        foreach ($this->interceptors as $interceptor) {
            $response = $interceptor->intercept($response);
        }

        return $response;
    }

    /**
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
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
     * Reads a request ahead of the dispatcher, refusing the reserved message ID the validation middleware would.
     *
     * @throws RequestValidationException
     * @throws ProtocolException
     * @throws UnsolicitedNotificationException
     * @throws ConnectionException
     */
    private function readAheadRequest(): LdapMessageRequest
    {
        $message = $this->readRequest(null);
        if ($message->getMessageId() === 0) {
            throw new RequestValidationException('The message ID 0 cannot be used in a client request.');
        }

        return $message;
    }
}
