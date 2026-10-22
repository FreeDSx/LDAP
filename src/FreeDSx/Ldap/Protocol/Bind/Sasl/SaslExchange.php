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
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\AnswerableExceptionInterface;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Exception\SaslNegotiationAbortedException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdResolver;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\MechanismOptionsBuilderFactory;
use FreeDSx\Ldap\Protocol\Bind\Sasl\UsernameExtractor\SaslUsernameExtractorFactory;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Middleware\CriticalControlValidator;
use FreeDSx\Ldap\Server\Operation\FailureAnswerTrait;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\SaslContext;
use Throwable;

/**
 * Drives the SASL challenge-response loop on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SaslExchange
{
    use FailureAnswerTrait;

    private const BIND_IN_PROGRESS = 'A SASL bind is in progress.';

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly ResponseFactory $responseFactory,
        private readonly MechanismOptionsBuilderFactory $optionsBuilderFactory,
        private readonly AuthzIdResolver $authzIdResolver,
        private readonly CriticalControlValidator $criticalControls,
        private readonly PasswordPolicyContext $policyContext,
        private readonly SaslUsernameExtractorFactory $usernameExtractorFactory = new SaslUsernameExtractorFactory(),
    ) {}

    /**
     * Runs the full SASL exchange until the mechanism reports completion.
     *
     * @throws OperationException if the client sends a non-SASL request mid-exchange.
     */
    public function run(SaslExchangeInput $input): SaslExchangeResult
    {
        $mechName = $input->getMechName();
        $optionsBuilder = $this->optionsBuilderFactory->make($mechName);
        $message = $input->getInitialMessage();

        /** @var Closure(?string): SaslContext $challengeProcessor */
        $challengeProcessor = function (?string $challengeReceived) use ($input, $optionsBuilder, $mechName): SaslContext {
            try {
                return $input->getChallenge()->challenge(
                    $challengeReceived,
                    $optionsBuilder->buildOptions($challengeReceived, $mechName),
                );
            } catch (SaslException $e) {
                // Re-thrown so it carries a bind result code.
                throw new OperationException(
                    'Invalid credentials.',
                    ResultCode::INVALID_CREDENTIALS,
                    $e,
                );
            }
        };

        try {
            $completed = $this->runExchangeLoop(
                $challengeProcessor,
                $input->getInitialCredentials(),
                $message,
                $mechName,
            );
            $context = $completed->context;

            $username = $optionsBuilder->getUsername() ?? $this->extractUsername(
                $completed->usernameCredentials,
                $mechName,
            );
            $resolvedDn = $optionsBuilder->getResolvedDn();
            // The authorizing identity is set only when an authzid is assumed, below.
            $authorizingDn = null;

            // A client-supplied authzid is honored uniformly here, after the mechanism authenticated.
            $effective = $this->honorAuthzId(
                $context,
                $username,
                $resolvedDn,
            );
            if ($effective !== null) {
                $username = $effective->getUsername();
                $resolvedDn = $effective->getResolvedDn();
                $authorizingDn = $effective->getAuthorizingDn();
            }
        } catch (ResponseAlreadySentException $e) {
            throw $e;
        } catch (AnswerableExceptionInterface $e) {
            // Once $message is a continuation, the outer ServerProtocolHandler holds a stale
            // initial-bind ID. Send the error here with the correct ID before re-throwing.
            if ($message !== $input->getInitialMessage()) {
                $failure = $this->answerFor($e) ?? throw $e;
                $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                    $message,
                    $failure->getCode(),
                    $failure->getMessage(),
                ));

                // Signals the dispatcher that this message is answered, so it does not add one for the initial ID.
                throw new ResponseAlreadySentException(
                    $failure->getMessage(),
                    $failure->getCode(),
                    $failure,
                );
            }

            throw $e;
        }

        return new SaslExchangeResult(
            $context,
            $message,
            $username,
            $resolvedDn,
            $authorizingDn,
            $completed->serverFinal,
        );
    }

    /**
     * Resolves a client-supplied authzid (when the mechanism carried one) to the effective identity.
     *
     * Returns the token to bind as, or null when there is no authzid to honor.
     *
     * @throws OperationException when the assumption is denied
     */
    private function honorAuthzId(
        SaslContext $context,
        ?string $username,
        ?Dn $resolvedDn,
    ): ?AuthenticatedTokenInterface {
        $rawAuthzId = $this->requestedAuthzId(
            $context->getAuthzId(),
            $username,
        );
        if ($rawAuthzId === null || $resolvedDn === null) {
            return null;
        }

        try {
            $effective = $this->assumeAuthzId(
                BindToken::fromSasl(
                    $username ?? $resolvedDn->toString(),
                    $resolvedDn,
                ),
                $rawAuthzId,
            );
        } catch (OperationException $e) {
            // RFC 4513 5 refuses the bind with invalidCredentials when the authzid may not be assumed.
            throw new OperationException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
                $e,
            );
        }

        return $effective instanceof AuthenticatedTokenInterface
            ? $effective
            : null;
    }

    /**
     * Assumes the requested authzid as the authenticated identity, returning the effective token.
     *
     * @throws OperationException when the authzid is malformed or may not be assumed.
     */
    private function assumeAuthzId(
        BindToken $authcToken,
        string $rawAuthzId,
    ): TokenInterface {
        try {
            $authzId = AuthzId::fromString($rawAuthzId);
        } catch (InvalidArgumentException) {
            $this->authzIdResolver->deny(
                $authcToken,
                $rawAuthzId,
            );
        }

        return $this->authzIdResolver->assume(
            $authcToken,
            $authzId,
        );
    }

    /**
     * The authzid to honor as a proxy request, or null when it is absent or names the authenticated identity itself.
     *
     * A client asking to act as its own authcId (the common case, e.g. PLAIN) needs no proxy authorization.
     */
    private function requestedAuthzId(
        ?string $rawAuthzId,
        ?string $authcId,
    ): ?string {
        if ($rawAuthzId === null || $rawAuthzId === '' || $rawAuthzId === $authcId) {
            return null;
        }

        return $rawAuthzId;
    }

    private function extractUsername(
        ?string $credentials,
        MechanismName $mechName,
    ): ?string {
        if ($credentials === null) {
            return null;
        }

        try {
            return $this->usernameExtractorFactory
                ->make($mechName)
                ->extractUsername(
                    $mechName,
                    $credentials,
                );
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Drives the challenge-response loop until the mechanism completes.
     *
     * $message is passed by reference so the caller's catch block always holds the latest message ID.
     *
     * @param Closure(?string): SaslContext $challengeProcessor
     * @throws OperationException
     */
    private function runExchangeLoop(
        Closure $challengeProcessor,
        ?string $received,
        LdapMessageRequest &$message,
        MechanismName $mechName,
    ): CompletedExchange {
        $prevContextResponse = null;
        // PLAIN: credentials are in $received from the start; others: first non-null continuation.
        $usernameCredentials = $received;

        while (true) {
            $advancement = $this->advanceChallenge(
                $challengeProcessor,
                $received,
                $prevContextResponse,
            );
            $prevContextResponse = $advancement->context->getResponse();
            if ($advancement->complete) {
                return new CompletedExchange(
                    $advancement->context,
                    $usernameCredentials,
                    $advancement->serverFinal,
                );
            }

            // Send the server's message to the client: a challenge, or an empty credential prompt
            // (e.g. PLAIN when credentials are absent from the initial bind).
            $this->sendBindInProgress(
                $message,
                $prevContextResponse,
            );

            // Update $message so the correct ID is available if an error occurs in a later step.
            $message = $this->nextMessage();
            $received = $this->requireSaslContinuation($message, $mechName)->getCredentials();

            if ($usernameCredentials === null && $received !== null) {
                $usernameCredentials = $received;
            }
        }
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

        // RFC 4513 5.2.1.2 lets server-final data ride out with the success notification, which is what a
        // client treating that data as terminal expects rather than a further round.
        if ($context->isComplete()) {
            return new ChallengeAdvancement(
                $context,
                complete: true,
                serverFinal: $contextResponse,
            );
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
     * A continuation never reaches the middleware. So we need per-message control handling applied here.
     *
     * @throws OperationException when a control the server does not recognise is marked critical.
     */
    private function applyContinuationControls(LdapMessageRequest $message): void
    {
        $controls = $message->controls();

        // RFC 4511 4.1.11 refuses the operation, and the continuation is part of the operation it refuses.
        $this->criticalControls->assertSupportedForBind($controls);

        // The continuation is the message that completes the bind, so a request made on it counts.
        if (!$controls->has(Control::OID_PWD_POLICY)) {
            return;
        }

        $this->policyContext->setResponseRequested(true);
    }

    /**
     * Reads the next message of the exchange, passing over an abandon since RFC 4511 4.11 makes a bind unabandonable.
     *
     * @throws RequestValidationException if a message carries an unusable message ID.
     */
    private function nextMessage(): LdapMessageRequest
    {
        do {
            $message = $this->queue->getMessage();

            // Continuations skip the validation middleware, and the challenge echoes back whatever ID arrives.
            if ($message->getMessageId() === 0) {
                throw new RequestValidationException('The message ID 0 cannot be used in a client request.');
            }
        } while ($message->getRequest() instanceof AbandonRequest);

        return $message;
    }

    /**
     * The message received mid-exchange, as a continuation of the mechanism currently running.
     *
     * @throws OperationException when an empty mechanism aborts, or the message is not a bind at all.
     * @throws SaslNegotiationAbortedException when another bind replaces the one in progress.
     * @throws ResponseAlreadySentException when an unbind ends the session, leaving the bind unanswered.
     */
    private function requireSaslContinuation(
        LdapMessageRequest $message,
        MechanismName $mechName,
    ): SaslBindRequest {
        $request = $message->getRequest();

        // RFC 4511 4.3 ends the session, so the bind goes unanswered and the unbind is handled as it normally is.
        if ($request instanceof UnbindRequest) {
            $this->queue->requeue($message);

            throw new ResponseAlreadySentException(
                self::BIND_IN_PROGRESS,
                ResultCode::OPERATIONS_ERROR,
            );
        }

        // RFC 4511 4.2.1 gives a client three ways to abandon a negotiation, and an empty mechanism is the
        // one the server answers itself rather than treating as a replacement bind.
        if ($request instanceof SaslBindRequest && $request->getMechanism() === '') {
            throw new OperationException(
                'The requested authentication type is not supported.',
                ResultCode::AUTH_METHOD_UNSUPPORTED,
            );
        }

        if ($request instanceof SaslBindRequest && $request->getMechanism() === $mechName->value) {
            $this->applyContinuationControls($message);

            return $request;
        }

        if ($request instanceof BindRequest) {
            throw new SaslNegotiationAbortedException($message);
        }

        // RFC 4511 4.2.1 forbids other operations between the steps of a bind, which makes this one out of sequence.
        throw new OperationException(
            self::BIND_IN_PROGRESS,
            ResultCode::OPERATIONS_ERROR,
        );
    }
}
