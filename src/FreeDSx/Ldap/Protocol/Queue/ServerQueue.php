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

use FreeDSx\Asn1\Encoder\EncoderInterface;
use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
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

use function strlen;

/**
 * The LDAP Queue class for sending and receiving messages for servers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerQueue extends LdapQueue implements ConnectionControl
{
    /**
     * @var LdapMessageRequest[]
     */
    private array $pendingMessages = [];

    /**
     * @var ResponseInterceptor[]
     */
    private readonly array $interceptors;

    /**
     * @param ResponseInterceptor[] $interceptors applied to every outgoing response, in order.
     */
    public function __construct(
        Socket $socket,
        ?EncoderInterface $encoder = null,
        int $maxReceiveSize = 0,
        array $interceptors = [],
        private readonly MetricsRecorderInterface $metricsRecorder = new NullMetricsRecorder(),
    ) {
        parent::__construct(
            $socket,
            $encoder,
            $maxReceiveSize,
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
        if ($id === null && $this->pendingMessages !== []) {
            return array_shift($this->pendingMessages);
        }

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
     * Checks whether an Abandon or Cancel targeting a message ID has arrived.
     *
     * Other messages received while peeking are buffered.
     */
    public function peekForCancelSignal(int $inFlightMessageId): ?LdapMessageRequest
    {
        if (!$this->hasPendingData()) {
            return null;
        }

        $message = $this->getMessage();
        $request = $message->getRequest();

        // Peeking skips the validation middleware, and a Cancel is acknowledged under the ID it arrives with. Buffering
        // an unusable one leaves the refusal to the middleware rather than tearing down the operation being streamed.
        if ($message->getMessageId() !== 0 && $this->isAbandonOrCancelRequest($request, $inFlightMessageId)) {
            return $message;
        }

        $this->pendingMessages[] = $message;

        return null;
    }

    /**
     * @throws EncoderException
     */
    public function sendMessage(LdapMessageResponse ...$response): self
    {
        $this->sendLdapMessage(array_map(
            $this->applyInterceptors(...),
            $response,
        ));

        return $this;
    }

    /**
     * Stream an iterable message response set out the socket.
     *
     * @param iterable<LdapMessageResponse> $responses
     * @throws EncoderException
     */
    public function sendMessages(iterable $responses): self
    {
        $this->sendLdapMessage($this->interceptLazily($responses));

        return $this;
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
        $this->metricsRecorder->trafficObserved(new TrafficObservation(
            bytesReceived: (int) $message->getLastPosition(),
        ));
    }

    /**
     * {@inheritDoc}
     * @throws ProtocolException
     * @throws EncoderException
     * @throws PartialPduException
     * @throws RuntimeException
     */
    protected function constructMessage(Message $message, ?int $id = null): LdapMessageRequest
    {
        $type = $message->getMessage();

        if (!$type instanceof AbstractType) {
            throw new ProtocolException('The message received is invalid.');
        }

        return LdapMessageRequest::fromAsn1($type);
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
            yield $this->applyInterceptors($response);
        }
    }

    private function applyInterceptors(LdapMessageResponse $response): LdapMessageResponse
    {
        foreach ($this->interceptors as $interceptor) {
            $response = $interceptor->intercept($response);
        }

        return $response;
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
}
