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

namespace FreeDSx\Ldap\Protocol\Bind;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ResponseAlreadySentException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchange;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchangeInput;
use FreeDSx\Ldap\Protocol\Bind\Sasl\SaslExchangeResult;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\MessageWrapper\SaslMessageWrapper;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\Auth\SaslBindPolicyEnforcer;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Sasl\Challenge\ChallengeInterface;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Sasl;
use FreeDSx\Sasl\SaslInterface;

/**
 * Handles a SASL bind request on the server side.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SaslBind implements BindInterface
{
    use VersionValidatorTrait;

    /**
     * @param string[] $mechanisms
     */
    public function __construct(
        private readonly ServerQueue $queue,
        private readonly SaslExchange $exchange,
        private readonly SaslInterface $sasl = new Sasl(),
        private readonly array $mechanisms = [],
        private readonly ResponseFactory $responseFactory = new ResponseFactory(),
        private readonly EventLogger $eventLogger = new EventLogger(null),
        private readonly ?SaslBindPolicyEnforcer $policyEnforcer = null,
    ) {}

    /**
     * {@inheritDoc}
     */
    public function supports(LdapMessageRequest $request): bool
    {
        return $request->getRequest() instanceof SaslBindRequest;
    }

    /**
     * {@inheritDoc}
     *
     * @throws OperationException
     */
    public function bind(LdapMessageRequest $message): TokenInterface
    {
        $request = $this->validateRequest($message);
        $mechNameStr = $request->getMechanism();
        $attemptedUsername = null;

        try {
            $this->validateMechanism($mechNameStr);

            $mechName = MechanismName::from($mechNameStr);

            $result = $this->exchange->run(new SaslExchangeInput(
                challenge: $this->getServerChallenge($mechName),
                mechName: $mechName,
                initialMessage: $message,
                initialCredentials: $request->getCredentials(),
            ));
            $attemptedUsername = $result->getUsername();

            $token = $this->finalize(
                $result,
                $mechName,
            );
        } catch (OperationException $e) {
            $this->eventLogger->recordFailure(
                ServerEvent::BindFailure,
                $e,
                [
                    EventContext::MECHANISM => $mechNameStr,
                    EventContext::VERSION => $request->getVersion(),
                ],
                subject: $attemptedUsername !== null
                    ? [EventContext::USERNAME => $attemptedUsername]
                    : null,
                message: $message,
            );

            throw $e;
        }

        $this->eventLogger->record(
            ServerEvent::BindSuccess,
            [
                EventContext::MECHANISM => $mechNameStr,
                EventContext::VERSION => $request->getVersion(),
            ],
            subject: $token,
            message: $message,
        );

        return $token;
    }

    /**
     * @throws RuntimeException
     * @throws OperationException
     */
    private function validateRequest(LdapMessageRequest $message): SaslBindRequest
    {
        $request = $message->getRequest();

        if (!$request instanceof SaslBindRequest) {
            throw new RuntimeException(sprintf(
                'Expected a SaslBindRequest, got: %s',
                get_class($request),
            ));
        }

        self::validateVersion($request);

        return $request;
    }

    /**
     * @throws OperationException
     */
    private function validateMechanism(string $mechName): void
    {
        if (!in_array($mechName, $this->mechanisms, true)) {
            throw new OperationException(
                sprintf('The SASL mechanism "%s" is not supported.', $mechName),
                ResultCode::AUTH_METHOD_UNSUPPORTED,
            );
        }
    }

    private function getServerChallenge(MechanismName $mechName): ChallengeInterface
    {
        return $this->sasl
            ->get($mechName)
            ->challenge(true);
    }

    /**
     * @throws OperationException
     * @throws EncoderException
     * @throws SaslException
     */
    private function finalize(
        SaslExchangeResult $result,
        MechanismName $mechName,
    ): TokenInterface {
        $context = $result->getContext();
        $message = $result->getLastMessage();

        if (!$context->isAuthenticated()) {
            $this->policyEnforcer?->recordFailure($result->getUsername());

            // Send the failure response directly using the current $message, which reflects
            // the latest message consumed from the queue (correct ID for multi-round exchanges).
            // Without this, the outer OperationException handler would use the stale first
            // message ID and the client would receive a response with the wrong message ID.
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                ResultCode::INVALID_CREDENTIALS,
                'Invalid credentials.',
            ));

            // The response was sent here, so signal the dispatcher not to send a second one.
            throw new ResponseAlreadySentException(
                'Invalid credentials.',
                ResultCode::INVALID_CREDENTIALS,
            );
        }

        try {
            $username = $result->getUsername();

            if ($username === null) {
                throw new OperationException(
                    sprintf('Unable to extract username for mechanism "%s".', $mechName->value),
                    ResultCode::PROTOCOL_ERROR,
                );
            }

            $resolvedDn = $result->getResolvedDn();

            if ($resolvedDn === null) {
                throw new OperationException(
                    'Invalid credentials.',
                    ResultCode::INVALID_CREDENTIALS,
                );
            }

            $this->policyEnforcer?->enforceSuccess(
                $username,
                $resolvedDn,
            );
        } catch (OperationException $e) {
            $this->queue->sendMessage($this->responseFactory->getStandardResponse(
                $message,
                $e->getCode(),
                $e->getMessage(),
            ));

            throw new ResponseAlreadySentException(
                $e->getMessage(),
                $e->getCode(),
                $e,
            );
        }

        // Captured before the queue interceptor clears the policy context on send.
        $mustChangePassword = $this->policyEnforcer?->mustChangePassword() ?? false;

        // The success response must be sent before activating the security layer.
        $this->queue->sendMessage(new LdapMessageResponse(
            $message->getMessageId(),
            new BindResponse(
                new LdapResult(ResultCode::SUCCESS),
                $result->getServerFinal(),
            ),
        ));

        if ($context->hasSecurityLayer()) {
            $mech = $this->sasl->get($mechName);
            $this->queue->setMessageWrapper(new SaslMessageWrapper($mech->securityLayer(), $context));
        }

        $token = BindToken::fromSasl(
            $username,
            $resolvedDn,
            authorizingDn: $result->getAuthorizingDn(),
        );
        if ($mustChangePassword) {
            $token->markMustChangePassword();
        }

        return $token;
    }
}
