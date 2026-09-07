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

namespace FreeDSx\Ldap\Server\Proxy;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;

/**
 * Relays a request to the upstream connection and relays the response back to the client.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ProxyRequestForwarder implements MiddlewareHandlerInterface
{
    public function __construct(
        private LdapClient $client,
        private ServerQueue $queue,
        private ProxyUpstreamSession $session,
        private ResponseFactory $responseFactory = new ResponseFactory(),
    ) {}

    /**
     * {@inheritDoc}
     */
    public function handle(ServerRequestContext $context): ResponseStream
    {
        $message = $context->message;
        $request = $message->getRequest();

        if ($request instanceof UnbindRequest) {
            $this->client->unbind();
            $this->queue->close();

            return ResponseStream::resolved(OperationOutcomeResult::succeeded());
        }

        // Synchronous, sequential forwarding means nothing is ever in flight upstream to abandon.
        if ($request instanceof AbandonRequest) {
            return ResponseStream::resolved(OperationOutcomeResult::succeeded());
        }

        if ($request instanceof SearchRequest) {
            $this->relayResultsAsTheyArrive(
                $request,
                $message->getMessageId(),
            );
        }

        try {
            $response = $this->sendUpstream(
                $request,
                array_values($message->controls()->toArray()),
            );
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
                $e->getMatchedDn(),
            ));

            return ResponseStream::resolved(OperationOutcomeResult::failed($e->getCode()));
        } catch (ReferralException $e) {
            // Only a search treats a referral as an ordinary result.
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                ResultCode::REFERRAL,
                $e->getMessage(),
                null,
                $e->getReferrals(),
            ));

            return ResponseStream::resolved(OperationOutcomeResult::failed(ResultCode::REFERRAL));
        }

        if ($request instanceof SearchRequest) {
            $this->relaySearch($message, $response);
        } else {
            $this->relaySingle($message, $response);
        }

        return ResponseStream::resolved(OperationOutcomeResult::succeeded());
    }

    /**
     * @param array<int, Control> $controls
     * @throws ConnectionException When a bound session loses the upstream identity it was answering for.
     * @throws OperationException
     */
    private function sendUpstream(
        RequestInterface $request,
        array $controls,
    ): LdapMessageResponse {
        try {
            $this->session->ensureEncrypted();

            return $this->client->sendAndReceive(
                $request,
                ...$controls,
            );
        } catch (ConnectionException $e) {
            // Reconnecting returns an anonymous session
            // Ending it beats answering as an identity we no longer are.
            if ($this->session->isBound()) {
                throw $e;
            }

            throw new OperationException(
                'The upstream LDAP server is unavailable.',
                ResultCode::UNAVAILABLE,
            );
        }
    }

    private function relaySingle(
        LdapMessageRequest $message,
        LdapMessageResponse $response,
    ): void {
        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            $response->getResponse(),
            ...$response->controls()->toArray(),
        ));
    }

    /**
     * An upstream PDU carried over under this client's message id, keeping whatever controls it arrived with.
     */
    private function relayed(
        int $messageId,
        LdapMessageResponse $upstream,
    ): LdapMessageResponse {
        return new LdapMessageResponse(
            $messageId,
            $upstream->getResponse(),
            ...$upstream->controls()->toArray(),
        );
    }

    /**
     * Hands each result to the client as it arrives, rather than collecting the whole set first.
     */
    private function relayResultsAsTheyArrive(
        SearchRequest $request,
        int $messageId,
    ): void {
        // Taken from the upstream message rather than the bare entry, so per-entry controls survive the hop.
        $request->useEntryHandler(function (EntryResult $result) use ($messageId): void {
            $this->queue->sendMessage($this->relayed(
                $messageId,
                $result->getMessage(),
            ));
        });

        $request->useReferralHandler(function (ReferralResult $result) use ($messageId): void {
            $this->queue->sendMessage($this->relayed(
                $messageId,
                $result->getMessage(),
            ));
        });
    }

    private function relaySearch(
        LdapMessageRequest $message,
        LdapMessageResponse $response,
    ): void {
        $searchResponse = $response->getResponse();

        if (!$searchResponse instanceof SearchResponse) {
            $this->relaySingle($message, $response);

            return;
        }

        // Only the terminal message is left to send.
        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new SearchResultDone(
                $searchResponse->getResultCode(),
                $searchResponse->getDn(),
                $searchResponse->getDiagnosticMessage(),
            ),
            ...$response->controls()->toArray(),
        ));
    }
}
