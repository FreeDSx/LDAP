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

namespace FreeDSx\Ldap\Protocol\Bind\Sasl;

use Closure;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Sasl\SaslContext;

/**
 * Drives the SASL challenge-response loop on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslExchange
{
    public function __construct(
        private readonly ServerQueue $queue,
        private readonly ResponseFactory $responseFactory,
        private readonly MechanismOptionsBuilderFactory $optionsBuilderFactory,
        private readonly PasswordAuthenticatableInterface $authenticator,
    ) {
    }

    /**
     * Runs the full SASL exchange until the mechanism reports completion.
     *
     * @throws OperationException if the client sends a non-SASL request mid-exchange.
     */
    public function run(SaslExchangeInput $input): SaslExchangeResult
    {
        $mechName = $input->getMechName();
        $optionsBuilder = $this->optionsBuilderFactory->make($mechName, $this->authenticator);
        $challenge = $input->getChallenge();
        $message = $input->getInitialMessage();
        $received = $input->getInitialCredentials();

        // Tracks the credentials that contain the username (differs per mechanism).
        // For PLAIN, it's the initial credentials. For challenge-based mechanisms,
        // it's the first non-null response received back from the client.
        $usernameCredentials = $received;
        $context = null;
        $prevContextResponse = null;

        /** @var Closure(?string): SaslContext $challengeProcessor */
        $challengeProcessor = fn(?string $challengeReceived): SaslContext => $challenge->challenge(
            $challengeReceived,
            $optionsBuilder->buildOptions($challengeReceived, $mechName),
        );

        while (true) {
            // DIGEST-MD5 re-entry: context is already complete from the previous iteration
            // (server-final sent, client ack received) — break to preserve the authenticated context.
            if ($context !== null && $context->isComplete()) {
                break;
            }

            $advancement = $this->advanceChallenge(
                $challengeProcessor,
                $received,
                $prevContextResponse,
            );
            $context = $advancement->context;
            $prevContextResponse = $context->getResponse();
            if ($advancement->complete) {
                break;
            }

            // Send the server's message to the client: a challenge, an empty credential prompt
            // (e.g. PLAIN when credentials are absent from the initial bind), or a server-final.
            $this->sendBindInProgress(
                $message,
                $prevContextResponse,
            );

            // Update $message before any throw so the correct ID is used if we send a
            // response directly (the outer handler always sees the first bind's ID).
            $message = $this->queue->getMessage();
            $nextRequest = $this->requireSaslContinuation($message);
            $received = $nextRequest->getCredentials();

            if ($usernameCredentials === null && $received !== null) {
                $usernameCredentials = $received;
            }
        }

        return new SaslExchangeResult(
            $context,
            $message,
            $usernameCredentials,
        );
    }

    /**
     * Advances the mechanism by one step and enforces all completion break conditions.
     *
     * @param Closure(?string): SaslContext $doChallenge
     */
    private function advanceChallenge(
        Closure $doChallenge,
        ?string $received,
        ?string $prevContextResponse,
    ): ChallengeAdvancement {
        $context = $doChallenge($received);
        $contextResponse = $context->getResponse();
        $responseIsNew = ($contextResponse !== $prevContextResponse);

        // Some mechanisms (e.g. CRAM-MD5) do not clear the context response after the final
        // validation step — the stale value from the previous round remains. By comparing to
        // what we sent last time we can detect this and avoid sending a spurious second round.
        if ($context->isComplete() && !$responseIsNew) {
            return new ChallengeAdvancement($context, complete: true);
        }

        // If the mechanism reports completion with a failure (e.g. SCRAM e=invalid-proof),
        // skip sending the server-final and fall through to the INVALID_CREDENTIALS path.
        // This avoids a protocol deadlock where the client throws a SaslException on
        // receiving the e= response and never sends the ack the server would wait for.
        if ($context->isComplete() && !$context->isAuthenticated()) {
            return new ChallengeAdvancement($context, complete: true);
        }

        return new ChallengeAdvancement($context, complete: false);
    }

    /**
     * Sends a SASL_BIND_IN_PROGRESS response carrying the server's challenge or server-final data.
     */
    private function sendBindInProgress(LdapMessageRequest $message, ?string $response): void
    {
        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new BindResponse(
                new LdapResult(ResultCode::SASL_BIND_IN_PROGRESS),
                $response,
            ),
        ));
    }

    /**
     * Validates that the message received mid-exchange is a SASL bind continuation.
     *
     * @throws OperationException if the client sends a non-SASL request.
     */
    private function requireSaslContinuation(LdapMessageRequest $message): SaslBindRequest
    {
        $request = $message->getRequest();

        if (!$request instanceof SaslBindRequest) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                ResultCode::PROTOCOL_ERROR,
                'Expected a SASL bind continuation during the exchange.',
            ));

            throw new OperationException(
                'Expected a SASL bind continuation during the exchange.',
                ResultCode::PROTOCOL_ERROR
            );
        }

        return $request;
    }
}
